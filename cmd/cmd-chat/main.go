// Command cmd-chat is the CMD-Chat terminal application.
//
// A running instance is always reachable. It binds the chat listener, answers
// LAN discovery, publishes to the phonebook and waits on the relay from the
// moment it opens, so there is no "host" role to choose: two people both open
// CMD-Chat, and whichever of them types the other's ID first becomes the guest.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/auth"
	"github.com/ESP32-S3/CMD-Chat/internal/chat"
	"github.com/ESP32-S3/CMD-Chat/internal/connect"
	"github.com/ESP32-S3/CMD-Chat/internal/debug"
	"github.com/ESP32-S3/CMD-Chat/internal/discovery"
	"github.com/ESP32-S3/CMD-Chat/internal/e2ee"
	"github.com/ESP32-S3/CMD-Chat/internal/identity"
	"github.com/ESP32-S3/CMD-Chat/internal/ipc"
	"github.com/ESP32-S3/CMD-Chat/internal/network"
	"github.com/ESP32-S3/CMD-Chat/internal/phonebook"
	"github.com/ESP32-S3/CMD-Chat/internal/profile"
	"github.com/ESP32-S3/CMD-Chat/internal/relay"
	"github.com/ESP32-S3/CMD-Chat/internal/update"
)

const tcpPort = 38556
const ipcAddress = "127.0.0.1:5050"

// version is stamped in at build time with
// -ldflags "-X main.version=v2.1.5". A build without it is a developer build,
// and the update check stays quiet rather than claiming it is out of date.
var version = "dev"

// name is the nickname shown next to this user's messages. It lives on this
// computer only; see internal/profile.
func name() string { return profile.Name() }

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--debug-child" {
		debugChild()
		return
	}
	defer crashGuard()
	id, err := identity.LoadOrCreate()
	if err != nil {
		fatal(err)
	}
	debug.Log("CMD-Chat started; args=%q", os.Args[1:])
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "id":
			fmt.Println(id.ID)
			return
		case "version", "--version", "-v":
			fmt.Println(version)
			return
		case "endpoint":
			endpoint()
			return
		case "host":
			host(id, argsAfter(2))
			return
		case "join":
			join(id, argsAfter(2))
			return
		case "forget":
			forget(argsAfter(2))
			return
		case "security":
			securityReport(id)
			return
		case "help", "--help", "-h":
			usage()
			return
		}
	}
	ready(id)
}

// argsAfter returns the command-line arguments following position n.
//
// os.Args[n:] panics outright when os.Args is shorter than n, and that is
// exactly what used to happen the moment someone picked "Start a chat" from the
// menu of a double-clicked launcher: os.Args held only the executable name, the
// process died before it opened a single socket, and the terminal window closed
// with the panic in it. Debug mode passed --debug-child, which made os.Args long
// enough for the slice to be legal - which is why the bug looked like it went
// away in debug mode and left only the firewall prompt behind.
func argsAfter(n int) []string {
	if len(os.Args) <= n {
		return nil
	}
	return os.Args[n:]
}

// newFlags builds a flag set that reports parse errors instead of exiting.
// flag.ExitOnError would kill the process, and with it the launcher window, over
// nothing worse than a mistyped flag.
func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	return fs
}

// crashGuard turns a panic into something a double-click user can act on.
//
// The packaged launchers run the executable directly, so the window closes the
// instant the process exits and an unhandled panic leaves no trace of itself.
// The launcher scripts hold the window open on a non-zero exit; this makes sure
// there is a readable explanation waiting there when they do.
func crashGuard() {
	r := recover()
	if r == nil {
		return
	}
	debug.Report(r)
	fmt.Println()
	fmt.Println("CMD-Chat hit an unexpected error and has to close:")
	fmt.Printf("  %v\n", r)
	fmt.Println()
	fmt.Println("Please report this at https://github.com/ESP32-S3/CMD-Chat/issues")
	if debug.Enabled() {
		fmt.Println("Details were written to the debug log.")
	} else {
		fmt.Println("Run the Debug option from the menu and reproduce it to capture a log.")
	}
	os.Exit(1)
}

// stdinLines pumps the keyboard onto a channel.
//
// A blocked read on os.Stdin cannot be cancelled, so it has to live somewhere
// other than the code doing the waiting: the ready prompt waits on a typed ID
// and an incoming peer at the same time, and the peer has to be able to win.
func stdinLines() <-chan string {
	ch := make(chan string)
	go func() {
		defer close(ch)
		s := bufio.NewScanner(os.Stdin)
		s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for s.Scan() {
			ch <- s.Text()
		}
	}()
	return ch
}

// checkForUpdate looks for a newer release in the background.
//
// It runs off the launch path entirely: the returned channel yields at most one
// release and is then closed, so a slow or unreachable GitHub delays nothing and
// a failure says nothing. The result is delivered to the prompt when it arrives
// rather than being waited for, because an update notice is never worth making
// someone wait to start a conversation.
func checkForUpdate() <-chan *update.Release {
	out := make(chan *update.Release, 1)
	go func() {
		defer debug.Contain("update check")
		defer close(out)
		if update.Disabled() {
			debug.Log("Update check disabled by %s", update.DisableEnv)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), update.Timeout)
		defer cancel()
		release, err := update.Check(ctx, version)
		if err != nil {
			debug.Log("Update check failed: %v", err)
			return
		}
		if release == nil {
			debug.Log("Update check: %s is current", version)
			return
		}
		debug.Log("Update available: %s -> %s", version, release.Version)
		out <- release
	}()
	return out
}

// announceUpdate prints the one notice an out-of-date build gets.
func announceUpdate(release *update.Release) {
	if release == nil {
		return
	}
	fmt.Println()
	fmt.Printf("A newer CMD-Chat is available: %s (you have %s).\n", release.Version, version)
	if release.URL != "" {
		fmt.Printf("Download it from %s\n", release.URL)
	}
	fmt.Println("You can keep chatting on this version; updating is optional.")
	fmt.Println()
}

// renderPacket prints one packet from the host and reports any roster it
// carried, so the caller can answer /who without a round trip.
//
// Everything printed here originates with the host, including the names beside
// other people's messages. A guest authenticates the host and nobody else; see
// the group chat note in the README.
func renderPacket(p chat.Packet) (roster []chat.Member, shown bool) {
	switch p.Type {
	case "msg":
		label := p.Name
		if label == "" {
			label = chat.ShortID(p.From)
		}
		fmt.Printf("\r[%s] %s\n", label, p.Text)
		return nil, true
	case "system":
		fmt.Printf("\r* %s\n", p.Text)
		return nil, true
	case "roster":
		// Silent by design: the join and leave notices already say what
		// changed, and reprinting the whole room over every arrival would bury
		// the conversation.
		return p.Members, true
	case "error":
		fmt.Printf("\r! %s\n", p.Text)
		return nil, true
	}
	return nil, false
}

// showPending prints messages that are already queued without waiting for more.
func showPending(ch chan chat.Packet) {
	for {
		select {
		case p := <-ch:
			renderPacket(p)
		default:
			return
		}
	}
}

// drain discards anything already queued on a channel, so an event from the
// previous chat is not delivered to the next one.
func drain[T any](ch chan T) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// station is everything that makes this computer reachable while CMD-Chat is
// open: the chat listener, LAN discovery, the phonebook listing, the relay
// standby and the local bridge.
type station struct {
	id    *identity.Identity
	host  *chat.Host
	port  int
	peers chan chat.Peer
	left  chan chat.Peer

	// direct records whether the TCP listener actually opened. When a firewall
	// refuses it, the relay still works and the chat still happens.
	direct bool

	stop []func()
}

func (s *station) close() {
	s.host.Disconnect()
	for i := len(s.stop) - 1; i >= 0; i-- {
		s.stop[i]()
	}
}

// openStation makes this computer reachable and returns once it is.
//
// Every CMD-Chat instance does this as soon as it starts. That is what removes
// the old split where one person had to pick "Start a chat" and the other "Join
// a chat" - both sides are already hosting, so whoever types an ID first becomes
// the guest and the other side is already there to answer.
func openStation(id *identity.Identity, port int, publish, relayEnabled bool) (*station, error) {
	h, err := chat.NewHost(id.ID, name(), id)
	if err != nil {
		return nil, err
	}

	h.SetGroup(profile.GroupChatEnabled())

	st := &station{id: id, host: h, port: port, peers: make(chan chat.Peer, 8), left: make(chan chat.Peer, 8)}
	h.OnPeer = func(p chat.Peer, gone bool) {
		if gone {
			debug.Log("Peer %s disconnected", p.ID)
			select {
			case st.left <- p:
			default:
			}
			return
		}
		debug.Log("Peer %s connected inbound", p.ID)
		select {
		case st.peers <- p:
		default:
		}
	}

	// Bind before anything else and check the error here rather than in a
	// background goroutine: on Windows this is where a cancelled firewall prompt
	// surfaces, and the user has to be told instead of being left with a
	// listener that silently never accepts.
	if err := h.Bind(port); err != nil {
		reportBlockedListener(err, port)
	} else {
		st.direct = true
		st.stop = append(st.stop, func() { _ = h.Close() })
		go func() {
			defer debug.Contain("chat listener")
			if err := h.Serve(); err != nil {
				debug.Log("Chat server stopped: %v", err)
			}
		}()
	}
	debug.Log("Station open; id=%s port=%d direct=%t fingerprint=%s", id.ID, port, st.direct, h.Fingerprint)

	startIPC(id, h)
	go func() {
		defer debug.Contain("LAN discovery")
		// A blocked or already-bound discovery socket only costs same-Wi-Fi
		// discovery, which the phonebook covers anyway, so it stays in the log
		// rather than alarming the user a second time.
		if err := discovery.Serve(discovery.Announcement{ID: id.ID, Name: name(), Port: port, Fingerprint: h.Fingerprint}); err != nil {
			debug.Log("LAN discovery stopped: %v", err)
		}
	}()

	if publish {
		st.stop = append(st.stop, serveRelay(id, h, relayEnabled))
		st.stop = append(st.stop, publishToPhonebook(id, port, h.Fingerprint, relayEnabled))
	} else {
		fmt.Println("Phonebook publishing disabled; only this LAN can find you.")
	}
	return st, nil
}

// reportBlockedListener explains a chat port that could not be opened.
//
// On Windows the usual cause is the "Windows Defender Firewall has blocked some
// features of this app" prompt being dismissed or cancelled. It is not fatal -
// the relay carries the chat either way - so this says what was lost, how to get
// it back, and carries on.
func reportBlockedListener(err error, port int) {
	debug.Log("Chat listener bind on port %d failed: %v", port, err)
	fmt.Println()
	fmt.Printf("Could not open port %d for direct connections.\n", port)
	switch {
	case isAddrInUse(err):
		fmt.Println("Another copy of CMD-Chat is already using it.")
		fmt.Println("Close the other CMD-Chat window, then start this one again.")
		return
	case runtime.GOOS == "windows":
		fmt.Println("Windows Firewall is blocking it. If you saw a prompt saying it had")
		fmt.Println("blocked some features of this app, choose Allow access next time.")
		fmt.Println("To fix it now: Windows Security > Firewall & network protection >")
		fmt.Println("Allow an app through firewall > Change settings > tick CMD-Chat.")
	default:
		fmt.Println("A local firewall is most likely blocking it.")
	}
	fmt.Println("You can still chat: CMD-Chat will use the encrypted relay instead.")
	fmt.Println()
}

// isAddrInUse reports the "port is taken" case. The error text is matched
// because the underlying errno differs between Windows (WSAEADDRINUSE) and the
// Unix platforms, and this only picks the wording of a message.
func isAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "address already in use") ||
		strings.Contains(text, "only one usage of each socket address")
}

// ready is the flow a double-clicked CMD-Chat lands in.
//
// There is nothing to start: this instance is reachable from the moment it
// opens. Either you paste a friend's ID and become the guest, or they paste
// yours first and you are already there to answer.
func ready(id *identity.Identity) {
	lines := stdinLines()
	updates := checkForUpdate()
	st, err := openStation(id, tcpPort, true, true)
	if err != nil {
		fatal(err)
	}
	defer st.close()

	banner(st)
	for {
		fmt.Print("> ")
		select {
		case line, ok := <-lines:
			if !ok {
				return
			}
			if !runCommand(st, strings.TrimSpace(line), lines) {
				return
			}
		case p := <-st.peers:
			fmt.Println()
			hostChat(st, p, lines)
		case release, ok := <-updates:
			// The channel closes once the check is done. Dropping the case
			// stops the loop spinning on a closed channel; the carriage return
			// keeps the prompt from being printed twice either way.
			fmt.Print("\r")
			if !ok {
				updates = nil
				continue
			}
			announceUpdate(release)
		}
	}
}

func banner(st *station) {
	fmt.Println("========================================")
	fmt.Printf("              CMD-Chat %s\n", version)
	fmt.Println("========================================")
	fmt.Printf("Your ID: %s\n", st.id.ID)
	fmt.Printf("You appear as: %s\n", name())
	fmt.Println()
	fmt.Println("You are reachable now. Nobody has to \"start\" or \"join\" anything.")
	fmt.Println("Send your ID to a friend, or paste theirs below - whoever types the")
	fmt.Println("other's ID first connects, and the other side just waits here.")
	if st.host.Group() {
		fmt.Println("More than one person can join you; they will all see each other.")
	} else {
		fmt.Println("Group chat is off: only one person at a time can join you.")
	}
	if !st.direct {
		fmt.Println()
		fmt.Println("Note: direct connections are blocked on this machine; the relay is in use.")
	}
	fmt.Println()
	fmt.Println("Type ? for help, or /quit to exit.")
	fmt.Println()
}

// setNickname stores a new nickname and reports the result. notify lets a live
// chat pick the change up without reconnecting.
func setNickname(argument string, notify func(string)) {
	wanted := profile.CleanNickname(argument)
	if argument != "" && wanted == "" {
		fmt.Println("That nickname has no printable characters in it.")
		fmt.Println()
		return
	}
	if err := profile.SetNickname(wanted); err != nil {
		fmt.Printf("Could not save the nickname: %v\n", err)
		fmt.Println()
		return
	}
	if notify != nil {
		notify(name())
	}
	if wanted == "" {
		fmt.Printf("Nickname cleared. You now appear as %s.\n", name())
	} else {
		fmt.Printf("You now appear as %s.\n", name())
	}
	fmt.Println("This is stored on this computer only - it is never published.")
	fmt.Println()
}

// setGroupChat stores the host's group-chat choice and applies it live.
func setGroupChat(st *station, argument string) {
	switch strings.ToLower(strings.TrimSpace(argument)) {
	case "on", "yes", "true", "enable", "enabled":
		apply(st, true)
	case "off", "no", "false", "disable", "disabled":
		apply(st, false)
	case "":
		if st.host.Group() {
			fmt.Println("Group chat is ON: several people can join you and will see each other.")
		} else {
			fmt.Println("Group chat is OFF: only one person at a time can join you.")
		}
		fmt.Println("Use /group on or /group off to change it.")
		fmt.Println()
	default:
		fmt.Println("Use /group on or /group off.")
		fmt.Println()
	}
}

func apply(st *station, enabled bool) {
	st.host.SetGroup(enabled)
	if err := profile.SetGroupChatEnabled(enabled); err != nil {
		debug.Log("Could not save the group-chat setting: %v", err)
		fmt.Printf("Applied for now, but could not save it for next time: %v\n", err)
	}
	if enabled {
		fmt.Println("Group chat is ON. Several people can join you, and they will see each other.")
	} else {
		fmt.Println("Group chat is OFF. Only one person at a time can join you.")
		if st.host.Count() > 1 {
			fmt.Println("Anyone already here stays; this applies to the next person who tries.")
		}
	}
	fmt.Println()
}

// showRoom prints who is in a room.
func showRoom(members []chat.Member, roomID string) {
	if len(members) == 0 {
		fmt.Println("Nobody else is here yet.")
		fmt.Println()
		return
	}
	fmt.Printf("%d in this room:\n", len(members))
	for _, m := range members {
		role := ""
		if m.Host {
			role = "   host"
		}
		fmt.Printf("  %-24s %s%s\n", m.Display(), chat.ShortID(m.ID), role)
	}
	if roomID != "" {
		fmt.Printf("Room ID: %s\n", roomID)
	}
	fmt.Println()
}

// showInvite explains which ID invites someone into this room.
//
// This is the one thing about group chat people get wrong: a guest's instinct is
// to share its own ID, which would open a separate chat instead of adding
// someone here. The room is always the host's ID.
func showInvite(roomID, ownID string, hosting bool) {
	fmt.Println()
	fmt.Println("Share this room's ID:")
	fmt.Println()
	fmt.Printf("    %s\n", roomID)
	fmt.Println()
	if hosting {
		fmt.Println("That is your own ID, because you are hosting. Anyone who pastes it joins you.")
	} else {
		fmt.Println("That is the host's ID, not yours. Anyone who pastes it lands in this room.")
		fmt.Printf("Your own ID (%s) would start a separate chat with you instead.\n", chat.ShortID(ownID))
	}
	fmt.Println()
}

// splitCommand separates a leading /command from its argument.
func splitCommand(text string) (string, string) {
	fields := strings.SplitN(text, " ", 2)
	command := strings.ToLower(strings.TrimSpace(fields[0]))
	if len(fields) == 1 {
		return command, ""
	}
	return command, strings.TrimSpace(fields[1])
}

// runCommand handles one line typed at the ready prompt. It returns false when
// CMD-Chat should exit.
func runCommand(st *station, text string, lines <-chan string) bool {
	if command, argument := splitCommand(text); strings.HasPrefix(command, "/") {
		switch command {
		case "/nick", "/name":
			setNickname(argument, func(n string) { st.host.SetName(n) })
			return true
		case "/group":
			setGroupChat(st, argument)
			return true
		case "/who", "/room":
			showRoom(st.host.Members(), st.id.ID)
			return true
		case "/invite":
			showInvite(st.id.ID, st.id.ID, true)
			return true
		}
	}
	switch strings.ToLower(text) {
	case "":
		return true
	case "5", "exit", "quit", "/quit", "/exit":
		return false
	case "3", "id", "/id":
		fmt.Printf("\nYour ID: %s\n\n", st.id.ID)
		fmt.Println("Give this ID to whoever wants to chat with you.")
		fmt.Println()
		return true
	case "4", "debug", "/debug":
		debugMenu(lines)
		return true
	case "?", "/?", "help", "/help":
		readyHelp(st)
		return true
	case "1", "2", "start", "host", "join":
		// The old menu numbers and verbs. Nothing needs starting any more, so
		// say so rather than pretending the option still exists.
		fmt.Println()
		fmt.Println("There is no separate start/join step any more - you are already hosting.")
		fmt.Printf("Share your ID (%s), or paste your friend's ID here.\n", st.id.ID)
		fmt.Println()
		return true
	}
	if !phonebook.ValidID(text) {
		fmt.Println("That does not look like a CMD-Chat ID. They look like cc-XXXXXXXXXXXXXXXX.")
		fmt.Println("Type ? for help.")
		return true
	}
	if strings.EqualFold(text, st.id.ID) {
		fmt.Println("That is your own ID. Paste your friend's ID instead.")
		return true
	}
	joinPeer(st, text, lines)
	return true
}

func readyHelp(st *station) {
	fmt.Println()
	fmt.Println("Paste a friend's ID and press Enter to connect to them.")
	fmt.Println("Or do nothing: they can connect to you at any time.")
	fmt.Println()
	fmt.Println("  /id            show your ID again")
	fmt.Println("  /nick NAME     set the name others see (stored on this computer only)")
	fmt.Println("  /group on|off  allow more than one person into chats you host")
	fmt.Println("  /who           list who is in the room")
	fmt.Println("  /verify        show the safety number to compare with the other person")
	fmt.Println("  /invite        show the ID that invites someone into this room")
	fmt.Println("  /debug         open a debug terminal and record a crash log")
	fmt.Println("  /quit          close CMD-Chat (also leaves a chat)")
	fmt.Println()
	fmt.Printf("Your ID: %s\n", st.id.ID)
	fmt.Printf("You appear as: %s\n", name())
	if st.host.Group() {
		fmt.Println("Group chat: ON - several people can join you and will see each other.")
	} else {
		fmt.Println("Group chat: OFF - only one person at a time can join you.")
	}
	if !st.direct {
		fmt.Println("Direct connections are blocked here; chats go over the relay.")
	}
	fmt.Println()
}

// hostChat runs the chat when other people connected to us.
//
// It holds the room open for as long as anyone is in it, rather than ending on
// the first departure: in a group chat one person leaving is an event, not the
// end of the conversation.
func hostChat(st *station, first chat.Peer, lines <-chan string) {
	drain(st.left)
	fmt.Printf("%s connected to you.\n", peerLabel(first))
	announceVerification(peerLabel(first), first.SafetyNumber, first.FirstContact)
	if st.host.Group() {
		fmt.Println("Others can join with /invite. /who lists the room. /quit ends it.")
	} else {
		fmt.Println("Type messages below. /quit leaves the chat.")
	}
	for {
		fmt.Print("> ")
		select {
		case line, ok := <-lines:
			if !ok {
				return
			}
			text := strings.TrimSpace(line)
			command, argument := splitCommand(text)
			switch command {
			case "/quit", "/exit":
				st.host.Disconnect()
				drain(st.left)
				drain(st.peers)
				fmt.Println("Left the chat. You are still reachable.")
				fmt.Println()
				return
			case "/who", "/room":
				showRoom(st.host.Members(), st.id.ID)
				continue
			case "/verify", "/safety":
				showVerification(peerLabel(first), first.SafetyNumber)
				continue
			case "/invite":
				showInvite(st.id.ID, st.id.ID, true)
				continue
			case "/nick", "/name":
				setNickname(argument, func(n string) { st.host.SetName(n) })
				continue
			case "/group":
				setGroupChat(st, argument)
				continue
			}
			if text == "" {
				continue
			}
			// Message text is deliberately never logged. See
			// docs/SECURITY-BASELINE.md, weakness W4: the debug log is a
			// world-readable file, and this used to write every outgoing
			// message into it in the clear.
			st.host.Broadcast(chat.Packet{Type: "msg", From: st.id.ID, Name: name(), Text: text})
			fmt.Printf("\r[%s] %s\n", name(), text)
		case p := <-st.peers:
			fmt.Printf("\r* %s joined - %d here\n", peerLabel(p), st.host.Count())
			announceVerification(peerLabel(p), p.SafetyNumber, p.FirstContact)
		case p := <-st.left:
			remaining := st.host.Count() - 1
			if remaining <= 0 {
				fmt.Printf("\r* %s left - the room is empty. You are still reachable.\n\n", peerLabel(p))
				return
			}
			fmt.Printf("\r* %s left - %d here\n", peerLabel(p), st.host.Count())
		}
	}
}

// announceVerification prints the safety number, and says plainly whether this
// is a peer we have talked to before.
//
// This is the one part of CMD-Chat's security that a user has to participate in.
// Everything else is checked by the software: the peer proves its identity key,
// the ID is a hash of that key, and a key that changes later fails the
// connection outright. What none of that can establish is whether the ID you
// were GIVEN was really your friend's — if it reached you through something the
// attacker controls, you are talking to exactly the identity you were handed.
//
// Comparing the safety number over a call, or in person, is what closes that.
func announceVerification(label, safetyNumber string, firstContact bool) {
	if safetyNumber == "" {
		return
	}
	fmt.Println()
	if firstContact {
		fmt.Printf("This is the first time you have connected to %s.\n", label)
		fmt.Println("From now on CMD-Chat will refuse the connection if their identity key changes.")
		fmt.Println("To be sure nobody is in the middle right now, check that you both see:")
	} else {
		fmt.Printf("You have connected to %s before, and their identity key is unchanged.\n", label)
		fmt.Println("Safety number:")
	}
	fmt.Println()
	fmt.Printf("    %s\n", safetyNumber)
	fmt.Println()
	if firstContact {
		fmt.Println("Read it to each other on a call, or compare screens. If it matches, nobody")
		fmt.Println("is between you. If it does not, stop and work out why. Type /verify to see")
		fmt.Println("it again at any time.")
		fmt.Println()
	}
}

// showVerification prints the safety number on demand, for /verify.
func showVerification(label, safetyNumber string) {
	fmt.Println()
	if safetyNumber == "" {
		fmt.Println("There is no active chat to verify.")
		fmt.Println()
		return
	}
	fmt.Printf("Safety number with %s:\n", label)
	fmt.Println()
	fmt.Printf("    %s\n", safetyNumber)
	fmt.Println()
	fmt.Println("Both of you should see exactly this. Compare it on a call or in person.")
	fmt.Println("It stays the same for this pair of people, and changes only if one of")
	fmt.Println("your identity keys changes.")
	fmt.Println()
}

// reportHandshakeFailure explains a refused connection.
//
// A changed identity key is singled out because it is the one failure a user
// must NOT be encouraged to retry past: it is either a friend who reinstalled,
// or somebody substituting their own key, and the software cannot tell which.
func reportHandshakeFailure(err error) {
	text := err.Error()
	fmt.Println()
	switch {
	case strings.Contains(text, "different identity key"):
		fmt.Println("Refusing to connect: that ID is using a different identity key than before.")
		fmt.Println()
		fmt.Println("Either they reinstalled CMD-Chat and lost their old identity, or somebody")
		fmt.Println("is trying to impersonate them. CMD-Chat cannot tell those apart, so it")
		fmt.Println("stops here rather than guessing.")
		fmt.Println()
		fmt.Println("Check with them by some other means - a call, in person, anything that is")
		fmt.Println("not this chat. If they really did reinstall, run:")
		fmt.Println()
		fmt.Println("    cmd-chat forget <their-id>")
		fmt.Println()
		fmt.Println("and connect again. You will be asked to compare a new safety number.")
	case strings.Contains(text, "fingerprint mismatch"):
		fmt.Println("Refusing to connect: the host's certificate is not the one that was published.")
		fmt.Println("Something is intercepting the connection, or the host restarted mid-lookup.")
		fmt.Println("Try again; if it keeps happening, do not proceed.")
	case strings.Contains(text, "identity mismatch"):
		fmt.Println("Refusing to connect: the peer that answered is not the ID you asked for.")
		fmt.Println("Do not proceed. Check the ID with your friend directly.")
	default:
		fmt.Printf("Connection failed: %v\n", err)
	}
	fmt.Println()
}

// peerLabel names a peer by nickname when it sent one, and by ID otherwise.
func peerLabel(p chat.Peer) string {
	if p.Name != "" {
		return fmt.Sprintf("%s (%s)", p.Name, chat.ShortID(p.ID))
	}
	return chat.ShortID(p.ID)
}

// joinPeer connects to a friend's ID from the ready prompt.
func joinPeer(st *station, target string, lines <-chan string) {
	debug.Log("Connection strategy started for %q", target)
	result, err := connect.Join(target, connect.Options{
		Identity:     st.id,
		PhonebookURL: phonebook.BaseURL(),
		RelayURL:     relay.BaseURL(),
		Log:          func(format string, args ...any) { fmt.Printf(format+"\n", args...) },
		Debug:        debug.Log,
		Force:        connect.ForceFromEnv(),
	})
	if err != nil {
		debug.Log("Connection strategy failed for %q: %v", target, err)
		fmt.Println("Could not reach that peer.")
		fmt.Println("Check the ID and make sure the other person has CMD-Chat open.")
		fmt.Println()
		return
	}
	debug.Log("Transport selected: path=%s detail=%s", result.Path, result.Detail)
	chatSession(st.id, result.Conn, result.Fingerprint, result.HostID, lines)
}

func debugMenu(lines <-chan string) {
	fmt.Println()
	fmt.Println("Debug / crash logs")
	if debug.Enabled() {
		fmt.Println("Debug logging: ENABLED")
		fmt.Println("Debug events and panic crash reports are being recorded.")
		fmt.Println()
		return
	}
	fmt.Println("This opens a second terminal running CMD-Chat in debug mode.")
	fmt.Println("Keep it open while reproducing the problem.")
	fmt.Print("Open debug terminal? (y/n): ")
	answer, ok := <-lines
	if !ok {
		return
	}
	answer = strings.TrimSpace(answer)
	if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
		fmt.Println("Debug logging remains disabled.")
		fmt.Println()
		return
	}
	if err := launchDebugTerminal(); err != nil {
		fmt.Printf("Could not open debug terminal: %v\n", err)
		fmt.Println()
		return
	}
	fmt.Println("Debug terminal opened. Reproduce the problem there.")
	fmt.Println()
}

func launchDebugTerminal() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	switch runtime.GOOS {
	case "windows":
		return exec.Command("cmd.exe", "/c", "start", "CMD-Chat Debug", exe, "--debug-child").Start()
	case "darwin":
		script := fmt.Sprintf("tell application \"Terminal\" to do script \"%s --debug-child\"", escapeAppleScript(exe))
		return exec.Command("osascript", "-e", script).Start()
	default:
		for _, t := range []string{"x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal", "xterm"} {
			if _, e := exec.LookPath(t); e != nil {
				continue
			}
			switch t {
			case "gnome-terminal":
				return exec.Command(t, "--", exe, "--debug-child").Start()
			case "konsole":
				return exec.Command(t, "-e", exe, "--debug-child").Start()
			case "xfce4-terminal":
				return exec.Command(t, "--command", exe+" --debug-child").Start()
			default:
				return exec.Command(t, "-e", exe, "--debug-child").Start()
			}
		}
		return fmt.Errorf("no supported terminal emulator was found")
	}
}

func escapeAppleScript(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\\", "\\\\"), "\"", "\\\"")
}

func debugChild() {
	defer crashGuard()
	path, err := debug.Enable()
	if err != nil {
		fmt.Printf("Could not enable debug logging: %v\n", err)
	} else {
		fmt.Println("CMD-Chat DEBUG MODE")
		fmt.Println("Crash/debug log:", path)
		fmt.Println("Keep this terminal open while reproducing the problem.")
		fmt.Println()
	}
	id, err := identity.LoadOrCreate()
	if err != nil {
		fatal(err)
	}
	ready(id)
}

// forget removes a remembered identity key, which is the only way past a
// key-change refusal.
//
// It is a separate, deliberate command precisely so that nothing on the network
// can trigger it. A prompt inside the failing connection would be a prompt an
// attacker had arranged.
func forget(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: cmd-chat forget <cmd-chat-id>")
		fmt.Println()
		fmt.Println("This makes CMD-Chat forget the identity key it remembers for that ID, so")
		fmt.Println("the next connection is treated as a first contact. Only do this after you")
		fmt.Println("have confirmed with the person, by some means other than this chat, that")
		fmt.Println("they really did change devices or reinstall.")
		return
	}
	target := strings.TrimSpace(args[0])
	if !phonebook.ValidID(target) {
		fmt.Println("That does not look like a CMD-Chat ID.")
		return
	}
	store := auth.Load()
	record, known := store.Known(target)
	if !known {
		fmt.Printf("Nothing is remembered for %s.\n", target)
		return
	}
	if err := store.Forget(target); err != nil {
		fmt.Printf("Could not forget it: %v\n", err)
		return
	}
	fmt.Printf("Forgot the identity key for %s.\n", target)
	if !record.FirstSeen.IsZero() {
		fmt.Printf("It had been trusted since %s.\n", record.FirstSeen.Format("2 January 2006"))
	}
	fmt.Println("The next connection will be treated as a first contact. Compare the new")
	fmt.Println("safety number with them before you say anything sensitive.")
}

// securityReport prints what is actually protecting this installation.
func securityReport(id *identity.Identity) {
	fmt.Println("CMD-Chat security status")
	fmt.Println()
	fmt.Printf("  Your ID              %s\n", id.ID)
	fmt.Printf("  Message encryption   %s (end to end, above TLS 1.3)\n", e2ee.ProtocolVersionName)
	fmt.Println("  Transport            TLS 1.3, certificate pinned where published")

	protection, err := identity.StoredProtection()
	switch {
	case err != nil:
		fmt.Printf("  Private key at rest  unknown (%v)\n", err)
	case protection == identity.ProtectionPassphrase:
		fmt.Println("  Private key at rest  encrypted with your passphrase (scrypt + XChaCha20-Poly1305)")
	case protection == identity.ProtectionDPAPI:
		fmt.Println("  Private key at rest  sealed by Windows to this user account (DPAPI)")
	default:
		fmt.Println("  Private key at rest  FILE PERMISSIONS ONLY")
		fmt.Printf("                       Set %s to encrypt it.\n", identity.PassphraseEnv)
	}

	store := auth.Load()
	if _, known := store.Known(id.ID); known {
		_ = known
	}
	fmt.Println()
	fmt.Println("What this does not protect:")
	fmt.Println("  - who you talk to, when, and roughly how much: the relay and the")
	fmt.Println("    phonebook see that, and encryption does not hide it")
	fmt.Println("  - anything on a device somebody else controls")
	fmt.Println()
	fmt.Println("See SECURITY.md in the repository for the full threat model.")
	fmt.Println("This code has not been independently audited.")
}

func usage() {
	fmt.Println("CMD-Chat - lightweight cross-platform terminal P2P chat")
	fmt.Println("Usage:")
	fmt.Println("  cmd-chat                 # open CMD-Chat; you are reachable immediately")
	fmt.Println("  cmd-chat id")
	fmt.Println("  cmd-chat version")
	fmt.Println("  cmd-chat endpoint")
	fmt.Println("  cmd-chat host [--port 38556] [--publish=false] [--relay=false] [--group=false]")
	fmt.Println("  cmd-chat join <persistent-id>        # LAN, then direct, then relay")
	fmt.Println("  cmd-chat forget <persistent-id>      # forget a remembered identity key")
	fmt.Println("  cmd-chat security                    # what is protecting this install")
	fmt.Println("  cmd-chat join --address host:port --fingerprint SHA256...")
	fmt.Println()
	fmt.Println("Opening CMD-Chat with no arguments already makes you reachable, so two")
	fmt.Println("people do not need to agree on who hosts: both open it, and whoever types")
	fmt.Println("the other's ID first connects. The host and join subcommands remain for")
	fmt.Println("scripts and for pinning one side of a connection.")
	fmt.Println()
	fmt.Println("Joining tries the local network first, then a direct connection using the")
	fmt.Println("addresses in the phonebook, and finally the relay if no direct path works.")
	fmt.Println("Hosting publishes your ID and address candidates so peers outside your LAN")
	fmt.Println("can find you; --publish=false stays LAN-only and --relay=false skips the relay.")
	fmt.Println()
	fmt.Printf("Phonebook: %s (override with %s)\n", phonebook.BaseURL(), phonebook.BaseURLEnv)
	fmt.Printf("Relay:     %s (override with %s)\n", relay.BaseURL(), relay.BaseURLEnv)
	fmt.Println("Set CMD_CHAT_TRANSPORT=lan|direct|relay to pin one path when diagnosing.")
	fmt.Println()
	fmt.Printf("This build: %s\n", version)
	fmt.Printf("On launch CMD-Chat asks GitHub whether a newer release exists and prints a\n")
	fmt.Printf("notice if one does. It sends nothing about you. Set %s=1 to turn it off.\n", update.DisableEnv)
}

func endpoint() {
	e, err := network.DiscoverPublicEndpoint()
	if err != nil {
		fatal(err)
	}
	debug.Log("Endpoint discovery: %s:%d", e.Address, e.Port)
	fmt.Printf("Public UDP endpoint: %s:%d\n", e.Address, e.Port)
	fmt.Println("This is a NAT-discovery result; it is not by itself a reachable TCP chat address.")
}

func startIPC(id *identity.Identity, h *chat.Host) {
	srv := ipc.Server{Address: ipcAddress, OnCommand: func(cmd ipc.Command) {
		debug.Log("IPC command: %s", cmd.Cmd)
		switch cmd.Cmd {
		case "status":
			fmt.Printf("IPC status requested by %s\n", cmd.ID)
		case "send":
			if strings.TrimSpace(cmd.Message) != "" {
				h.Broadcast(chat.Packet{Type: "msg", From: id.ID, Name: name(), Text: cmd.Message})
			}
		}
	}}
	go func() {
		defer debug.Contain("local bridge")
		// The bridge only serves the optional ChromeOS frontend, and it is bound
		// to loopback, so a second instance losing the port is not worth telling
		// the user about.
		if err := srv.Listen(); err != nil {
			debug.Log("IPC bridge stopped: %v", err)
		}
	}()
}

// host runs the explicit hosting subcommand: reachable, but never dialling out.
func host(id *identity.Identity, args []string) {
	fs := newFlags("host")
	port := fs.Int("port", tcpPort, "TCP listen port")
	publish := fs.Bool("publish", true, "publish this host to the public phonebook so peers outside this LAN can find it")
	relayEnabled := fs.Bool("relay", true, "also wait on the relay so peers with no direct path can still connect")
	group := fs.Bool("group", profile.GroupChatEnabled(), "let more than one person join, and let them see each other")
	if err := fs.Parse(args); err != nil {
		return
	}

	lines := stdinLines()
	updates := checkForUpdate()
	st, err := openStation(id, *port, *publish, *relayEnabled)
	if err != nil {
		fatal(err)
	}
	defer st.close()

	st.host.SetGroup(*group)
	fmt.Printf("Your ID: %s\nHosting chat for %s\nFingerprint: %s\n", id.ID, id.ID, st.host.Fingerprint)
	fmt.Printf("You appear as: %s\n", name())
	if *group {
		fmt.Println("Group chat is on; several people can join and will see each other.")
	} else {
		fmt.Println("Group chat is off; only one person at a time can join.")
	}
	fmt.Println("IPC bridge: ", ipcAddress)
	fmt.Println("Waiting for someone to connect. Type messages below; /quit exits.")
	fmt.Println("When someone joins, compare the safety number with them out of band.")
	for {
		fmt.Print("> ")
		select {
		case line, ok := <-lines:
			if !ok {
				return
			}
			text := strings.TrimSpace(line)
			if text == "/quit" {
				return
			}
			if text == "" {
				continue
			}
			// Never logged; see the note in hostChat.
			st.host.Broadcast(chat.Packet{Type: "msg", From: id.ID, Name: name(), Text: text})
			fmt.Printf("\r[%s] %s\n", name(), text)
		case p := <-st.peers:
			fmt.Printf("\r%s connected to you.\n", peerLabel(p))
			announceVerification(peerLabel(p), p.SafetyNumber, p.FirstContact)
		case p := <-st.left:
			fmt.Printf("\r%s left the chat.\n", peerLabel(p))
		case release, ok := <-updates:
			fmt.Print("\r")
			if !ok {
				updates = nil
				continue
			}
			announceUpdate(release)
		}
	}
}

// publishToPhonebook registers this host in the public rendezvous directory and
// keeps the entry alive. The returned function withdraws it again.
//
// Failure here is never fatal: the phonebook only adds reachability for peers
// outside this LAN, and LAN discovery keeps working without it.
func publishToPhonebook(id *identity.Identity, port int, fingerprint string, relayEnabled bool) func() {
	pb := phonebook.New(id, phonebook.BaseURL())
	fmt.Println("Publishing to the phonebook so peers outside this LAN can find you...")
	candidates, stunErr := phonebook.GatherCandidates(port, network.DiscoverPublicEndpoint)
	if stunErr != nil {
		debug.Log("STUN discovery failed: %v", stunErr)
		fmt.Println("Public UDP discovery failed; only local and routable addresses were published.")
	}
	// Version 2 tells joiners this host is also waiting on the relay, so a peer
	// with no direct path knows there is still a way through.
	version := 1
	if relayEnabled {
		version = connect.RelayProtocolVersion
	}
	announcement := phonebook.Announcement{Fingerprint: fingerprint, Candidates: candidates, ProtocolVersion: version}
	announce := func(ctx context.Context) error { _, err := pb.Register(ctx, announcement); return err }
	ctx, cancel := context.WithCancel(context.Background())
	registerCtx, registerCancel := context.WithTimeout(ctx, 15*time.Second)
	defer registerCancel()
	reg, err := pb.Register(registerCtx, announcement)
	if err != nil {
		cancel()
		debug.Log("Phonebook registration failed: %v", err)
		fmt.Printf("Phonebook registration failed: %v\n", err)
		fmt.Println("Others can still join from this LAN.")
		return func() {}
	}
	debug.Log("Phonebook registration ok; candidates=%d ttl=%d observed_ip=%s", len(candidates), reg.TTL, reg.ObservedIP)
	fmt.Printf("Listed in the phonebook as %s (%d address candidate(s), refreshed every %s).\n", id.ID, len(candidates), reg.HeartbeatIntervalDuration())
	go func() {
		defer debug.Contain("phonebook heartbeat")
		pb.KeepAlive(ctx, reg.HeartbeatIntervalDuration(), announce, func(err error) { debug.Log("Phonebook heartbeat failed: %v", err) })
	}()
	return func() {
		cancel()
		removeCtx, removeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer removeCancel()
		if err := pb.Unregister(removeCtx); err != nil {
			debug.Log("Phonebook unregister failed: %v", err)
		} else {
			debug.Log("Phonebook entry withdrawn")
		}
	}
}

// serveRelay keeps this host reachable through the relay while it is hosting.
// It never replaces the TCP listener: a guest that can connect directly always
// does, and only an unreachable guest ends up relayed.
func serveRelay(id *identity.Identity, h *chat.Host, enabled bool) func() {
	if !enabled {
		fmt.Println("Relay disabled; peers with no direct path will not be able to reach you.")
		return func() {}
	}
	stop := make(chan struct{})
	go func() {
		defer debug.Contain("relay standby")
		connect.ServeRelay(h, id, relay.BaseURL(), func(format string, args ...any) { fmt.Printf(format+"\n", args...) }, debug.Log, stop)
	}()
	fmt.Println("Relay standby active; peers behind strict NAT can still reach you.")
	return func() { close(stop) }
}

// join reaches a peer by ID, letting internal/connect pick the transport, or
// dials an explicit address when one is supplied.
func join(id *identity.Identity, args []string) {
	fs := newFlags("join")
	address := fs.String("address", "", "host:port")
	fingerprint := fs.String("fingerprint", "", "SHA-256 certificate fingerprint")
	if err := fs.Parse(args); err != nil {
		return
	}

	lines := stdinLines()

	// An explicit address skips discovery entirely; the user has already told us
	// exactly where the host is.
	if *address != "" {
		fmt.Printf("Connecting to %s...\n", *address)
		raw, err := net.DialTimeout("tcp", *address, chat.DialTimeout)
		if err != nil {
			debug.Log("Manual dial to %s failed: %v", *address, err)
			fmt.Printf("Connection failed: %v\n", err)
			return
		}
		chatSession(id, raw, *fingerprint, "", lines)
		return
	}

	target := id.ID
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}
	target = strings.TrimSpace(target)
	if !phonebook.ValidID(target) {
		fmt.Println("That does not look like a CMD-Chat ID.")
		return
	}

	debug.Log("Connection strategy started for %q", target)
	result, err := connect.Join(target, connect.Options{
		Identity:     id,
		PhonebookURL: phonebook.BaseURL(),
		RelayURL:     relay.BaseURL(),
		Log:          func(format string, args ...any) { fmt.Printf(format+"\n", args...) },
		Debug:        debug.Log,
		Force:        connect.ForceFromEnv(),
	})
	if err != nil {
		debug.Log("Connection strategy failed for %q: %v", target, err)
		fmt.Println("Could not reach that peer.")
		fmt.Println("Check the ID and make sure the other device has CMD-Chat open.")
		return
	}

	debug.Log("Transport selected: path=%s detail=%s", result.Path, result.Detail)
	chatSession(id, result.Conn, result.Fingerprint, result.HostID, lines)
}

// chatSession runs the TLS handshake, the CMDC1 end-to-end handshake and then
// the interactive loop. The transport may be LAN, direct or relayed;
// authentication and encryption are identical in every case.
func chatSession(id *identity.Identity, transport net.Conn, fingerprint, expectedHostID string, lines <-chan string) {
	debug.Log("Starting chat session; expectedHostID=%q pinned=%t", expectedHostID, fingerprint != "")
	c, err := chat.ClientConn(transport, fingerprint, expectedHostID, name(), id)
	if err != nil {
		debug.Log("Handshake failed: %v", err)
		fmt.Printf("Connection failed: %v\n", err)
		_ = transport.Close()
		return
	}
	defer c.Close()

	hello, err := c.Receive()
	if err != nil {
		debug.Log("Handshake decode failed: %v", err)
		fmt.Printf("Connection failed during handshake: %v\n", err)
		return
	}
	// A host that will not take this connection says so instead of greeting.
	// Turning that into "invalid host handshake" would report the one case with
	// a perfectly good explanation as a protocol fault.
	if hello.Type == "error" {
		// The reason is shown to the user but not written to the log: it is
		// text the peer chose, and the log is a file that gets shared.
		debug.Log("Host refused the connection")
		reason := strings.TrimSpace(hello.Text)
		if reason == "" {
			reason = "the host refused the connection"
		}
		fmt.Printf("Could not join: %s\n", reason)
		fmt.Println()
		return
	}
	if hello.Type != "hello" {
		debug.Log("Invalid host handshake packet: %+v", hello)
		fmt.Println("Connection failed: invalid host handshake")
		return
	}
	hostLabel := hello.Name
	if hostLabel == "" {
		hostLabel = chat.ShortID(hello.From)
	}
	fmt.Printf("Authenticated host %s (%s).\n", hostLabel, hello.From)
	announceVerification(hostLabel, c.SafetyNumber(), c.FirstContact())

	// roomID is the host's ID. That, and never this guest's own ID, is what
	// invites another person into this room.
	roomID := hello.From
	if roomID == "" {
		roomID = expectedHostID
	}
	if hello.Group {
		fmt.Println("This is a group room. /who lists everyone; /invite shows how to add someone.")
	} else {
		fmt.Println("Type messages below. /quit leaves the chat.")
	}

	// members is the host's most recent account of the room. Each roster packet
	// replaces it wholesale rather than merging, so a departure cannot be missed
	// by losing one update.
	var members []chat.Member

	// Incoming messages are handed to the loop below rather than printed from
	// the reader goroutine, so that one place owns the prompt. Printing from
	// both left a stray "> " behind every message.
	incoming := make(chan chat.Packet, 32)

	// leaving releases the reader goroutine if the loop below has already gone,
	// so a full buffer cannot strand it on a send nobody will receive.
	leaving := make(chan struct{})
	defer close(leaving)

	// closed reports the far end going away, so a dead chat returns to the
	// prompt instead of leaving the user typing into a closed socket.
	closed := make(chan struct{})
	go func() {
		defer debug.Contain("chat read loop")
		defer close(closed)
		chat.ReadLoop(c, func(p chat.Packet) {
			switch p.Type {
			case "msg", "roster", "system", "error":
			default:
				return
			}
			debug.Log("Packet type %q received", p.Type)
			select {
			case incoming <- p:
			case <-leaving:
			}
		})
	}()

	for {
		fmt.Print("> ")
		select {
		case p := <-incoming:
			if updated, shown := renderPacket(p); shown {
				if updated != nil {
					members = updated
				}
			}
		case line, ok := <-lines:
			if !ok {
				return
			}
			text := strings.TrimSpace(line)
			command, argument := splitCommand(text)
			switch command {
			case "/quit", "/exit":
				fmt.Println("Left the chat. You are still reachable.")
				fmt.Println()
				return
			case "/who", "/room":
				showRoom(members, roomID)
				continue
			case "/verify", "/safety":
				showVerification(hostLabel, c.SafetyNumber())
				continue
			case "/invite":
				showInvite(roomID, id.ID, false)
				continue
			case "/nick", "/name":
				setNickname(argument, func(n string) {
					if err := c.Rename(n); err != nil {
						debug.Log("Rename failed: %v", err)
					}
				})
				continue
			case "/group":
				fmt.Println("Only the host of a room can turn group chat on or off.")
				fmt.Println()
				continue
			}
			if text == "" {
				continue
			}
			if err := c.Send(chat.Packet{Type: "msg", From: id.ID, Name: name(), Text: text}); err != nil {
				debug.Log("Send failed: %v", err)
				fmt.Printf("Send failed: %v\n", err)
				return
			}
		case <-closed:
			// Anything that arrived just before the far end hung up is still
			// worth showing.
			showPending(incoming)
			fmt.Println("\rThe chat was closed. You are still reachable.")
			fmt.Println()
			return
		}
	}
}

func fatal(err error) {
	debug.Log("Fatal error: %v", err)
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
