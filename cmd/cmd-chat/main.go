package main

import (
 "bufio"
 "context"
 "errors"
 "flag"
 "fmt"
 "net"
 "os"
 "os/exec"
 "runtime"
 "strings"
 "time"
 "github.com/ESP32-S3/CMD-Chat/internal/chat"
 "github.com/ESP32-S3/CMD-Chat/internal/debug"
 "github.com/ESP32-S3/CMD-Chat/internal/discovery"
 "github.com/ESP32-S3/CMD-Chat/internal/identity"
 "github.com/ESP32-S3/CMD-Chat/internal/ipc"
 "github.com/ESP32-S3/CMD-Chat/internal/network"
 "github.com/ESP32-S3/CMD-Chat/internal/phonebook"
)
const tcpPort=38556
const ipcAddress="127.0.0.1:5050"
func name() string { if v:=os.Getenv("USERNAME");v!=""{return v};if v:=os.Getenv("USER");v!=""{return v};return "user" }
func main(){
 if len(os.Args)>1&&os.Args[1]=="--debug-child"{debugChild();return}
 defer debug.Recover();id,err:=identity.LoadOrCreate();if err!=nil{fatal(err)};debug.Log("CMD-Chat started; args=%q",os.Args[1:])
 if len(os.Args)>1{switch os.Args[1]{case "id":fmt.Println(id.ID);return;case "endpoint":endpoint();return;case "host":host(id);return;case "join":join(id,os.Args[2:]);return;case "help","--help","-h":usage();return}}
 interactive(id)
}
func interactive(id *identity.Identity){r:=bufio.NewReader(os.Stdin);for{fmt.Println("========================================");fmt.Println("              CMD-Chat");fmt.Println("========================================");fmt.Println("1) Start a chat");fmt.Println("2) Join a chat");fmt.Println("3) Show my ID");fmt.Println("4) Debug / crash logs");fmt.Println("5) Exit");fmt.Println();fmt.Print("> ");choice,err:=r.ReadString('\n');if err!=nil{return};switch strings.TrimSpace(choice){case "1":host(id);return;case "2":fmt.Print("Friend's ID: ");target,err:=r.ReadString('\n');if err!=nil{return};target=strings.TrimSpace(target);if target==""{fmt.Println("ID cannot be empty.");continue};join(id,[]string{target});fmt.Println();continue;case "3":fmt.Printf("\nYour ID: %s\n\n",id.ID);fmt.Println("Give this ID to someone who wants to join your chat.");fmt.Println();case "4":debugMenu(r);case "5":return;default:fmt.Println("Please choose 1, 2, 3, 4, or 5.");fmt.Println()}}}
func debugMenu(r *bufio.Reader){fmt.Println();fmt.Println("Debug / crash logs");if debug.Enabled(){fmt.Println("Debug logging: ENABLED");fmt.Println("Debug events and panic crash reports are being recorded.");fmt.Println();return};fmt.Println("This opens a second terminal running CMD-Chat in debug mode.");fmt.Println("Keep it open while reproducing the problem.");fmt.Print("Open debug terminal? (y/n): ");a,err:=r.ReadString('\n');if err!=nil{return};if !strings.EqualFold(strings.TrimSpace(a),"y")&&!strings.EqualFold(strings.TrimSpace(a),"yes"){fmt.Println("Debug logging remains disabled.");fmt.Println();return};if err:=launchDebugTerminal();err!=nil{fmt.Printf("Could not open debug terminal: %v\n",err);fmt.Println();return};fmt.Println("Debug terminal opened. Reproduce the problem there.");fmt.Println()}
func launchDebugTerminal()error{exe,err:=os.Executable();if err!=nil{return err};switch runtime.GOOS{case "windows":return exec.Command("cmd.exe","/c","start","CMD-Chat Debug",exe,"--debug-child").Start();case "darwin":script:=fmt.Sprintf("tell application \"Terminal\" to do script \"%s --debug-child\"",escapeAppleScript(exe));return exec.Command("osascript","-e",script).Start();default:for _,t:=range []string{"x-terminal-emulator","gnome-terminal","konsole","xfce4-terminal","xterm"}{if _,e:=exec.LookPath(t);e!=nil{continue};switch t{case "gnome-terminal":return exec.Command(t,"--",exe,"--debug-child").Start();case "konsole":return exec.Command(t,"-e",exe,"--debug-child").Start();case "xfce4-terminal":return exec.Command(t,"--command",exe+" --debug-child").Start();default:return exec.Command(t,"-e",exe,"--debug-child").Start()}};return fmt.Errorf("no supported terminal emulator was found")}}
func escapeAppleScript(s string)string{return strings.ReplaceAll(strings.ReplaceAll(s,"\\","\\\\"),"\"","\\\"")}
func debugChild(){defer debug.Recover();path,err:=debug.Enable();if err!=nil{fmt.Printf("Could not enable debug logging: %v\n",err)}else{fmt.Println("CMD-Chat DEBUG MODE");fmt.Println("Crash/debug log:",path);fmt.Println("Keep this terminal open while reproducing the problem.");fmt.Println()};id,err:=identity.LoadOrCreate();if err!=nil{fatal(err)};interactive(id)}
func usage(){fmt.Println("CMD-Chat - lightweight cross-platform terminal P2P chat");fmt.Println("Usage:");fmt.Println("  cmd-chat                 # open the terminal menu");fmt.Println("  cmd-chat id");fmt.Println("  cmd-chat endpoint");fmt.Println("  cmd-chat host [--port 38556] [--publish=false]");fmt.Println("  cmd-chat join <persistent-id>        # LAN discovery, then phonebook");fmt.Println("  cmd-chat join --address host:port --fingerprint SHA256...");fmt.Println();fmt.Println("Hosting publishes your ID and address candidates to the public phonebook so");fmt.Println("peers outside your LAN can find you. Use --publish=false to stay LAN-only.");fmt.Printf("Phonebook: %s (override with %s)\n",phonebook.BaseURL(),phonebook.BaseURLEnv)}
func endpoint(){e,err:=network.DiscoverPublicEndpoint();if err!=nil{fatal(err)};debug.Log("Endpoint discovery: %s:%d",e.Address,e.Port);fmt.Printf("Public UDP endpoint: %s:%d\n",e.Address,e.Port);fmt.Println("This is a NAT-discovery result; it is not by itself a reachable TCP chat address.")}
func startIPC(id *identity.Identity,h *chat.Host){srv:=ipc.Server{Address:ipcAddress,OnCommand:func(cmd ipc.Command){debug.Log("IPC command: %s",cmd.Cmd);switch cmd.Cmd{case "status":fmt.Printf("IPC status requested by %s\n",cmd.ID);case "send":if strings.TrimSpace(cmd.Message)!=""{h.Broadcast(chat.Packet{Type:"msg",From:id.ID,Name:name(),Text:cmd.Message})}}}};go func(){defer debug.Recover();if err:=srv.Listen();err!=nil{debug.Log("IPC bridge stopped: %v",err);fmt.Printf("IPC bridge stopped: %v\n",err)}}()}
func host(id *identity.Identity){fs:=flag.NewFlagSet("host",flag.ExitOnError);port:=fs.Int("port",tcpPort,"TCP listen port");publish:=fs.Bool("publish",true,"publish this host to the public phonebook so peers outside this LAN can find it");_=fs.Parse(os.Args[2:]);h,err:=chat.NewHost(id.ID,name(),id);if err!=nil{fatal(err)};debug.Log("Hosting chat; id=%s port=%d fingerprint=%s",id.ID,*port,h.Fingerprint);startIPC(id,h);go func(){defer debug.Recover();if err:=discovery.Serve(discovery.Announcement{ID:id.ID,Name:name(),Port:*port,Fingerprint:h.Fingerprint});err!=nil{debug.Log("LAN discovery stopped: %v",err);fmt.Printf("LAN discovery stopped: %v\n",err)}}();go func(){defer debug.Recover();if err:=h.Listen(*port);err!=nil{debug.Log("Chat server stopped: %v",err);fmt.Printf("Chat server stopped: %v\n",err)}}();fmt.Printf("Your ID: %s\nHosting chat for %s\nFingerprint: %s\n",id.ID,id.ID,h.Fingerprint);if *publish{defer publishToPhonebook(id,*port,h.Fingerprint)()}else{fmt.Println("Phonebook publishing disabled; only this LAN can find you.")};fmt.Println("IPC bridge: ",ipcAddress);fmt.Println("Type messages below. /quit exits.");input:=bufio.NewScanner(os.Stdin);fmt.Print("> ");for input.Scan(){text:=strings.TrimSpace(input.Text());if text=="/quit"{return};if text==""{fmt.Print("> ");continue};debug.Log("Host message sent: %q",text);h.Broadcast(chat.Packet{Type:"msg",From:id.ID,Name:name(),Text:text});fmt.Printf("\r[%s] %s\n> ",name(),text)}}

// publishToPhonebook registers this host in the public rendezvous directory and
// keeps the entry alive. The returned function withdraws it again.
//
// Failure here is never fatal: the phonebook only adds reachability for peers
// outside this LAN, and LAN discovery keeps working without it.
func publishToPhonebook(id *identity.Identity,port int,fingerprint string)func(){
 pb:=phonebook.New(id,phonebook.BaseURL())
 fmt.Println("Publishing to the phonebook so peers outside this LAN can find you...")
 candidates,stunErr:=phonebook.GatherCandidates(port,network.DiscoverPublicEndpoint)
 if stunErr!=nil{debug.Log("STUN discovery failed: %v",stunErr);fmt.Println("Public UDP discovery failed; only local and routable addresses were published.")}
 announce:=func(ctx context.Context)error{_,err:=pb.Register(ctx,phonebook.Announcement{Fingerprint:fingerprint,Candidates:candidates});return err}
 ctx,cancel:=context.WithCancel(context.Background())
 registerCtx,registerCancel:=context.WithTimeout(ctx,15*time.Second);defer registerCancel()
 reg,err:=pb.Register(registerCtx,phonebook.Announcement{Fingerprint:fingerprint,Candidates:candidates})
 if err!=nil{cancel();debug.Log("Phonebook registration failed: %v",err);fmt.Printf("Phonebook registration failed: %v\n",err);fmt.Println("Others can still join from this LAN.");return func(){}}
 debug.Log("Phonebook registration ok; candidates=%d ttl=%d observed_ip=%s",len(candidates),reg.TTL,reg.ObservedIP)
 fmt.Printf("Listed in the phonebook as %s (%d address candidate(s), refreshed every %s).\n",id.ID,len(candidates),reg.HeartbeatIntervalDuration())
 go func(){defer debug.Recover();pb.KeepAlive(ctx,reg.HeartbeatIntervalDuration(),announce,func(err error){debug.Log("Phonebook heartbeat failed: %v",err)})}()
 return func(){
  cancel()
  removeCtx,removeCancel:=context.WithTimeout(context.Background(),5*time.Second);defer removeCancel()
  if err:=pb.Unregister(removeCtx);err!=nil{debug.Log("Phonebook unregister failed: %v",err)}else{debug.Log("Phonebook entry withdrawn")}
 }}
func join(id *identity.Identity,args []string){fs:=flag.NewFlagSet("join",flag.ExitOnError);address:=fs.String("address","","host:port");fingerprint:=fs.String("fingerprint","","SHA-256 certificate fingerprint");_=fs.Parse(args);if *address!=""{connect(id,*address,*fingerprint,"");return};target:=id.ID;if fs.NArg()>0{target=fs.Arg(0)};target=strings.TrimSpace(target);debug.Log("LAN search started for ID=%q",target);fmt.Printf("Searching this LAN for %s...\n",target);found,err:=discovery.Find(target,3*time.Second);if err!=nil{debug.Log("LAN discovery error: %v",err);fmt.Printf("LAN discovery failed: %v\n",err);return};debug.Log("LAN search finished for %q: %d result(s)",target,len(found));if len(found)==0{fmt.Println("No LAN host found for that ID; checking the phonebook...");if joinViaPhonebook(id,target){return};fmt.Println("Check the ID and make sure the other device is hosting a chat.");return};for i,a:=range found{fmt.Printf("[%d] %s (%s)\n",i+1,a.Name,a.Endpoint)};a:=found[0];debug.Log("LAN host selected: id=%q endpoint=%q fingerprint=%q",a.ID,a.Endpoint,a.Fingerprint);connect(id,a.Endpoint,a.Fingerprint,a.ID)}

// joinViaPhonebook resolves a peer through the public directory when LAN
// discovery finds nothing, and connects to the first address that answers.
//
// Note on NAT traversal: the phonebook also publishes the peer's STUN-derived
// UDP mapping (see Peer.UDPEndpoints), but CMD-Chat's chat transport is TLS over
// TCP, so a UDP hole punch would not open the path this function needs. Direct
// connection therefore succeeds when the host is publicly routable or has a
// forwarded port, and fails behind symmetric NAT or CGNAT. There is no relay
// fallback; network.Relay is still an unimplemented interface.
func joinViaPhonebook(id *identity.Identity,target string)bool{
 if !phonebook.ValidID(target){fmt.Println("That does not look like a CMD-Chat ID.");return false}
 pb:=phonebook.New(id,phonebook.BaseURL())
 ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second);defer cancel()
 peer,err:=pb.Lookup(ctx,target)
 if err!=nil{
  debug.Log("Phonebook lookup for %q failed: %v",target,err)
  switch{
  case errors.Is(err,phonebook.ErrNotFound):fmt.Println("That ID has never been listed in the phonebook.")
  case errors.Is(err,phonebook.ErrOffline):fmt.Println("That ID is in the phonebook but is not online right now.")
  default:fmt.Printf("Phonebook lookup failed: %v\n",err)
  }
  return false}
 endpoints:=peer.TCPEndpoints()
 debug.Log("Phonebook resolved %s: %d candidate(s), %d dialable",peer.ID,len(peer.Candidates),len(endpoints))
 if len(endpoints)==0{fmt.Println("The phonebook has no reachable TCP address for that peer.");return false}
 for _,address:=range endpoints{
  fmt.Printf("Trying %s...\n",address)
  if !reachable(address){debug.Log("Phonebook candidate %s did not accept a connection",address);continue}
  connect(id,address,peer.Fingerprint,peer.ID)
  return true}
 fmt.Println("Found that peer in the phonebook, but none of its addresses accepted a connection.")
 fmt.Println("This usually means NAT or a firewall is blocking direct access. CMD-Chat has no relay fallback.")
 if observed:=peer.ObservedIPs();len(observed)>0{fmt.Printf("The peer was last seen from %s; a forwarded port on that address would work.\n",strings.Join(observed,", "))}
 return false}

// reachable probes a candidate before handing it to the TLS handshake, so a
// dead address costs one short timeout instead of a failed connection attempt.
func reachable(address string)bool{c,err:=net.DialTimeout("tcp",address,4*time.Second);if err!=nil{return false};_=c.Close();return true}
func connect(id *identity.Identity,address,fingerprint,expectedHostID string){fmt.Printf("Connecting to %s...\n",address);debug.Log("Connecting to %s expectedHostID=%q fingerprint=%q",address,expectedHostID,fingerprint);c,dec,err:=chat.Client(address,fingerprint,expectedHostID,id.ID,name(),id);if err!=nil{debug.Log("Connection failed: %v",err);fmt.Printf("Connection failed: %v\n",err);return};defer c.Close();var hello chat.Packet;if err:=dec.Decode(&hello);err!=nil{debug.Log("Handshake decode failed: %v",err);fmt.Printf("Connection failed during handshake: %v\n",err);return};if hello.Type!="hello"{debug.Log("Invalid host handshake packet: %+v",hello);fmt.Println("Connection failed: invalid host handshake");return};fmt.Printf("Authenticated host %s (%s).\n",hello.Name,hello.From);go func(){defer debug.Recover();chat.ReadLoop(dec,func(p chat.Packet){if p.Type=="msg"{debug.Log("Message received from %s",p.From);fmt.Printf("\r[%s] %s\n> ",p.Name,p.Text)}})}();input:=bufio.NewScanner(os.Stdin);fmt.Print("> ");for input.Scan(){text:=strings.TrimSpace(input.Text());if text=="/quit"{return};if text==""{fmt.Print("> ");continue};if err:=chat.Send(c,chat.Packet{Type:"msg",From:id.ID,Name:name(),Text:text});err!=nil{debug.Log("Send failed: %v",err);fmt.Printf("Send failed: %v\n",err);return};fmt.Print("> ")}}
func fatal(err error){debug.Log("Fatal error: %v",err);fmt.Fprintln(os.Stderr,"error:",err);os.Exit(1)}
