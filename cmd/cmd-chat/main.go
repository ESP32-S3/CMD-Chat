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

	"github.com/ESP32-S3/CMD-Chat/internal/chat"
	"github.com/ESP32-S3/CMD-Chat/internal/connect"
	"github.com/ESP32-S3/CMD-Chat/internal/debug"
	"github.com/ESP32-S3/CMD-Chat/internal/discovery"
	"github.com/ESP32-S3/CMD-Chat/internal/identity"
	"github.com/ESP32-S3/CMD-Chat/internal/ipc"
	"github.com/ESP32-S3/CMD-Chat/internal/network"
	"github.com/ESP32-S3/CMD-Chat/internal/phonebook"
	"github.com/ESP32-S3/CMD-Chat/internal/relay"
	"github.com/ESP32-S3/CMD-Chat/internal/update"
)

const tcpPort = 38556
const ipcAddress = "127.0.0.1:5050"

// version is stamped in at build time with
// -ldflags "-X main.version=v2.1.5". A build without it is a developer build,
// and the update check stays quiet rather than claiming it is out of date.
var version = "dev"

func name() string {
	if v := os.Getenv("USERNAME"); v != "" {
		return v
	}
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	return "user"
}

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

// showPending prints messages that are already queued without waiting for more.
func showPending(ch chan chat.Packet) {
	for {
		select {
		case p := <-ch:
			fmt.Printf("\r[%s] %s\n", p.Name, p.Text)
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
	fmt.Println()
	fmt.Println("You are reachable now. Nobody has to \"start\" or \"join\" anything.")
	fmt.Println("Send your ID to a friend, or paste theirs below - whoever types the")
	fmt.Println("other's ID first connects, and the other side just waits here.")
	if !st.direct {
		fmt.Println()
		fmt.Println("Note: direct connections are blocked on this machine; the relay is in use.")
	}
	fmt.Println()
	fmt.Println("Type ? for help, or /quit to exit.")
	fmt.Println()
}

// runCommand handles one line typed at the ready prompt. It returns false when
// CMD-Chat should exit.
func runCommand(st *station, text string, lines <-chan string) bool {
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
	fmt.Println("  /id      show your ID again")
	fmt.Println("  /debug   open a debug terminal and record a crash log")
	fmt.Println("  /quit    close CMD-Chat (also leaves a chat)")
	fmt.Println()
	fmt.Printf("Your ID: %s\n", st.id.ID)
	if !st.direct {
		fmt.Println("Direct connections are blocked here; chats go over the relay.")
	}
	fmt.Println()
}

// hostChat runs the chat when the other side connected to us.
func hostChat(st *station, p chat.Peer, lines <-chan string) {
	drain(st.left)
	fmt.Printf("%s connected to you.\n", p.ID)
	fmt.Println("Type messages below. /quit leaves the chat.")
	for {
		fmt.Print("> ")
		select {
		case line, ok := <-lines:
			if !ok {
				return
			}
			text := strings.TrimSpace(line)
			if text == "/quit" {
				st.host.Disconnect()
				drain(st.left)
				fmt.Println("Left the chat. You are still reachable.")
				fmt.Println()
				return
			}
			if text == "" {
				continue
			}
			debug.Log("Host message sent: %q", text)
			st.host.Broadcast(chat.Packet{Type: "msg", From: st.id.ID, Name: name(), Text: text})
			fmt.Printf("\r[%s] %s\n", name(), text)
		case <-st.left:
			fmt.Println("\rThe other side left the chat. You are still reachable.")
			fmt.Println()
			return
		}
	}
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

func usage() {
	fmt.Println("CMD-Chat - lightweight cross-platform terminal P2P chat")
	fmt.Println("Usage:")
	fmt.Println("  cmd-chat                 # open CMD-Chat; you are reachable immediately")
	fmt.Println("  cmd-chat id")
	fmt.Println("  cmd-chat version")
	fmt.Println("  cmd-chat endpoint")
	fmt.Println("  cmd-chat host [--port 38556] [--publish=false] [--relay=false]")
	fmt.Println("  cmd-chat join <persistent-id>        # LAN, then direct, then relay")
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

	fmt.Printf("Your ID: %s\nHosting chat for %s\nFingerprint: %s\n", id.ID, id.ID, st.host.Fingerprint)
	fmt.Println("IPC bridge: ", ipcAddress)
	fmt.Println("Waiting for someone to connect. Type messages below; /quit exits.")
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
			debug.Log("Host message sent: %q", text)
			st.host.Broadcast(chat.Packet{Type: "msg", From: id.ID, Name: name(), Text: text})
			fmt.Printf("\r[%s] %s\n", name(), text)
		case p := <-st.peers:
			fmt.Printf("\r%s connected to you.\n", p.ID)
		case p := <-st.left:
			fmt.Printf("\r%s left the chat.\n", p.ID)
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

// chatSession runs the TLS and identity handshake over an already-established
// transport, then the interactive loop. The transport may be LAN, direct or
// relayed; authentication is identical in every case.
func chatSession(id *identity.Identity, transport net.Conn, fingerprint, expectedHostID string, lines <-chan string) {
	debug.Log("Starting chat session; expectedHostID=%q pinned=%t", expectedHostID, fingerprint != "")
	c, dec, err := chat.ClientConn(transport, fingerprint, expectedHostID, id.ID, name(), id)
	if err != nil {
		debug.Log("Handshake failed: %v", err)
		fmt.Printf("Connection failed: %v\n", err)
		_ = transport.Close()
		return
	}
	defer c.Close()

	var hello chat.Packet
	if err := dec.Decode(&hello); err != nil {
		debug.Log("Handshake decode failed: %v", err)
		fmt.Printf("Connection failed during handshake: %v\n", err)
		return
	}
	if hello.Type != "hello" {
		debug.Log("Invalid host handshake packet: %+v", hello)
		fmt.Println("Connection failed: invalid host handshake")
		return
	}
	fmt.Printf("Authenticated host %s (%s).\n", hello.Name, hello.From)
	fmt.Println("Type messages below. /quit leaves the chat.")

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
		chat.ReadLoop(dec, func(p chat.Packet) {
			if p.Type != "msg" {
				return
			}
			debug.Log("Message received from %s", p.From)
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
			fmt.Printf("\r[%s] %s\n", p.Name, p.Text)
		case line, ok := <-lines:
			if !ok {
				return
			}
			text := strings.TrimSpace(line)
			if text == "/quit" {
				fmt.Println("Left the chat. You are still reachable.")
				fmt.Println()
				return
			}
			if text == "" {
				continue
			}
			if err := chat.Send(c, chat.Packet{Type: "msg", From: id.ID, Name: name(), Text: text}); err != nil {
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
