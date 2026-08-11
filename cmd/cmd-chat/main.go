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
func usage(){fmt.Println("CMD-Chat - lightweight cross-platform terminal P2P chat");fmt.Println("Usage:");fmt.Println("  cmd-chat                 # open the terminal menu");fmt.Println("  cmd-chat id");fmt.Println("  cmd-chat endpoint");fmt.Println("  cmd-chat host [--port 38556] [--publish=false] [--relay=false]");fmt.Println("  cmd-chat join <persistent-id>        # LAN, then direct, then relay");fmt.Println("  cmd-chat join --address host:port --fingerprint SHA256...");fmt.Println();fmt.Println("Joining tries the local network first, then a direct connection using the");fmt.Println("addresses in the phonebook, and finally the relay if no direct path works.");fmt.Println("Hosting publishes your ID and address candidates so peers outside your LAN");fmt.Println("can find you; --publish=false stays LAN-only and --relay=false skips the relay.");fmt.Println();fmt.Printf("Phonebook: %s (override with %s)\n",phonebook.BaseURL(),phonebook.BaseURLEnv);fmt.Printf("Relay:     %s (override with %s)\n",relay.BaseURL(),relay.BaseURLEnv);fmt.Println("Set CMD_CHAT_TRANSPORT=lan|direct|relay to pin one path when diagnosing.")}
func endpoint(){e,err:=network.DiscoverPublicEndpoint();if err!=nil{fatal(err)};debug.Log("Endpoint discovery: %s:%d",e.Address,e.Port);fmt.Printf("Public UDP endpoint: %s:%d\n",e.Address,e.Port);fmt.Println("This is a NAT-discovery result; it is not by itself a reachable TCP chat address.")}
func startIPC(id *identity.Identity,h *chat.Host){srv:=ipc.Server{Address:ipcAddress,OnCommand:func(cmd ipc.Command){debug.Log("IPC command: %s",cmd.Cmd);switch cmd.Cmd{case "status":fmt.Printf("IPC status requested by %s\n",cmd.ID);case "send":if strings.TrimSpace(cmd.Message)!=""{h.Broadcast(chat.Packet{Type:"msg",From:id.ID,Name:name(),Text:cmd.Message})}}}};go func(){defer debug.Recover();if err:=srv.Listen();err!=nil{debug.Log("IPC bridge stopped: %v",err);fmt.Printf("IPC bridge stopped: %v\n",err)}}()}
func host(id *identity.Identity){fs:=flag.NewFlagSet("host",flag.ExitOnError);port:=fs.Int("port",tcpPort,"TCP listen port");publish:=fs.Bool("publish",true,"publish this host to the public phonebook so peers outside this LAN can find it");relayEnabled:=fs.Bool("relay",true,"also wait on the relay so peers with no direct path can still connect");_=fs.Parse(os.Args[2:]);h,err:=chat.NewHost(id.ID,name(),id);if err!=nil{fatal(err)};debug.Log("Hosting chat; id=%s port=%d fingerprint=%s",id.ID,*port,h.Fingerprint);startIPC(id,h);go func(){defer debug.Recover();if err:=discovery.Serve(discovery.Announcement{ID:id.ID,Name:name(),Port:*port,Fingerprint:h.Fingerprint});err!=nil{debug.Log("LAN discovery stopped: %v",err);fmt.Printf("LAN discovery stopped: %v\n",err)}}();go func(){defer debug.Recover();if err:=h.Listen(*port);err!=nil{debug.Log("Chat server stopped: %v",err);fmt.Printf("Chat server stopped: %v\n",err)}}();fmt.Printf("Your ID: %s\nHosting chat for %s\nFingerprint: %s\n",id.ID,id.ID,h.Fingerprint);if *publish{stopRelay:=serveRelay(id,h,*relayEnabled);defer stopRelay();defer publishToPhonebook(id,*port,h.Fingerprint,*relayEnabled)()}else{fmt.Println("Phonebook publishing disabled; only this LAN can find you.")};fmt.Println("IPC bridge: ",ipcAddress);fmt.Println("Type messages below. /quit exits.");input:=bufio.NewScanner(os.Stdin);fmt.Print("> ");for input.Scan(){text:=strings.TrimSpace(input.Text());if text=="/quit"{return};if text==""{fmt.Print("> ");continue};debug.Log("Host message sent: %q",text);h.Broadcast(chat.Packet{Type:"msg",From:id.ID,Name:name(),Text:text});fmt.Printf("\r[%s] %s\n> ",name(),text)}}

// publishToPhonebook registers this host in the public rendezvous directory and
// keeps the entry alive. The returned function withdraws it again.
//
// Failure here is never fatal: the phonebook only adds reachability for peers
// outside this LAN, and LAN discovery keeps working without it.
func publishToPhonebook(id *identity.Identity,port int,fingerprint string,relayEnabled bool)func(){
 pb:=phonebook.New(id,phonebook.BaseURL())
 fmt.Println("Publishing to the phonebook so peers outside this LAN can find you...")
 candidates,stunErr:=phonebook.GatherCandidates(port,network.DiscoverPublicEndpoint)
 if stunErr!=nil{debug.Log("STUN discovery failed: %v",stunErr);fmt.Println("Public UDP discovery failed; only local and routable addresses were published.")}
 // Version 2 tells joiners this host is also waiting on the relay, so a peer
 // with no direct path knows there is still a way through.
 version:=1
 if relayEnabled{version=connect.RelayProtocolVersion}
 announcement:=phonebook.Announcement{Fingerprint:fingerprint,Candidates:candidates,ProtocolVersion:version}
 announce:=func(ctx context.Context)error{_,err:=pb.Register(ctx,announcement);return err}
 ctx,cancel:=context.WithCancel(context.Background())
 registerCtx,registerCancel:=context.WithTimeout(ctx,15*time.Second);defer registerCancel()
 reg,err:=pb.Register(registerCtx,announcement)
 if err!=nil{cancel();debug.Log("Phonebook registration failed: %v",err);fmt.Printf("Phonebook registration failed: %v\n",err);fmt.Println("Others can still join from this LAN.");return func(){}}
 debug.Log("Phonebook registration ok; candidates=%d ttl=%d observed_ip=%s",len(candidates),reg.TTL,reg.ObservedIP)
 fmt.Printf("Listed in the phonebook as %s (%d address candidate(s), refreshed every %s).\n",id.ID,len(candidates),reg.HeartbeatIntervalDuration())
 go func(){defer debug.Recover();pb.KeepAlive(ctx,reg.HeartbeatIntervalDuration(),announce,func(err error){debug.Log("Phonebook heartbeat failed: %v",err)})}()
 return func(){
  cancel()
  removeCtx,removeCancel:=context.WithTimeout(context.Background(),5*time.Second);defer removeCancel()
  if err:=pb.Unregister(removeCtx);err!=nil{debug.Log("Phonebook unregister failed: %v",err)}else{debug.Log("Phonebook entry withdrawn")}
 }}
// serveRelay keeps this host reachable through the relay while it is hosting.
// It never replaces the TCP listener: a guest that can connect directly always
// does, and only an unreachable guest ends up relayed.
func serveRelay(id *identity.Identity,h *chat.Host,enabled bool)func(){
 if !enabled{fmt.Println("Relay disabled; peers with no direct path will not be able to reach you.");return func(){}}
 stop:=make(chan struct{})
 go func(){defer debug.Recover();connect.ServeRelay(h,id,relay.BaseURL(),func(format string,args ...any){fmt.Printf(format+"\n",args...)},debug.Log,stop)}()
 fmt.Println("Relay standby active; peers behind strict NAT can still reach you.")
 return func(){close(stop)}}

// join reaches a peer by ID, letting internal/connect pick the transport, or
// dials an explicit address when one is supplied.
func join(id *identity.Identity,args []string){
 fs:=flag.NewFlagSet("join",flag.ExitOnError)
 address:=fs.String("address","","host:port")
 fingerprint:=fs.String("fingerprint","","SHA-256 certificate fingerprint")
 _=fs.Parse(args)

 // An explicit address skips discovery entirely; the user has already told us
 // exactly where the host is.
 if *address!=""{
  fmt.Printf("Connecting to %s...\n",*address)
  raw,err:=net.DialTimeout("tcp",*address,chat.DialTimeout)
  if err!=nil{debug.Log("Manual dial to %s failed: %v",*address,err);fmt.Printf("Connection failed: %v\n",err);return}
  chatSession(id,raw,*fingerprint,"")
  return}

 target:=id.ID
 if fs.NArg()>0{target=fs.Arg(0)}
 target=strings.TrimSpace(target)
 if !phonebook.ValidID(target){fmt.Println("That does not look like a CMD-Chat ID.");return}

 debug.Log("Connection strategy started for %q",target)
 result,err:=connect.Join(target,connect.Options{
  Identity:id,
  PhonebookURL:phonebook.BaseURL(),
  RelayURL:relay.BaseURL(),
  Log:func(format string,args ...any){fmt.Printf(format+"\n",args...)},
  Debug:debug.Log,
  Force:connect.ForceFromEnv(),
 })
 if err!=nil{
  debug.Log("Connection strategy failed for %q: %v",target,err)
  fmt.Println("Could not reach that peer.")
  fmt.Println("Check the ID and make sure the other device is hosting a chat.")
  return}

 debug.Log("Transport selected: path=%s detail=%s",result.Path,result.Detail)
 chatSession(id,result.Conn,result.Fingerprint,result.HostID)}

// chatSession runs the TLS and identity handshake over an already-established
// transport, then the interactive loop. The transport may be LAN, direct or
// relayed; authentication is identical in every case.
func chatSession(id *identity.Identity,transport net.Conn,fingerprint,expectedHostID string){debug.Log("Starting chat session; expectedHostID=%q pinned=%t",expectedHostID,fingerprint!="");c,dec,err:=chat.ClientConn(transport,fingerprint,expectedHostID,id.ID,name(),id);if err!=nil{debug.Log("Handshake failed: %v",err);fmt.Printf("Connection failed: %v\n",err);_=transport.Close();return};defer c.Close();var hello chat.Packet;if err:=dec.Decode(&hello);err!=nil{debug.Log("Handshake decode failed: %v",err);fmt.Printf("Connection failed during handshake: %v\n",err);return};if hello.Type!="hello"{debug.Log("Invalid host handshake packet: %+v",hello);fmt.Println("Connection failed: invalid host handshake");return};fmt.Printf("Authenticated host %s (%s).\n",hello.Name,hello.From);go func(){defer debug.Recover();chat.ReadLoop(dec,func(p chat.Packet){if p.Type=="msg"{debug.Log("Message received from %s",p.From);fmt.Printf("\r[%s] %s\n> ",p.Name,p.Text)}})}();input:=bufio.NewScanner(os.Stdin);fmt.Print("> ");for input.Scan(){text:=strings.TrimSpace(input.Text());if text=="/quit"{return};if text==""{fmt.Print("> ");continue};if err:=chat.Send(c,chat.Packet{Type:"msg",From:id.ID,Name:name(),Text:text});err!=nil{debug.Log("Send failed: %v",err);fmt.Printf("Send failed: %v\n",err);return};fmt.Print("> ")}}
func fatal(err error){debug.Log("Fatal error: %v",err);fmt.Fprintln(os.Stderr,"error:",err);os.Exit(1)}
