package identity

import("os";"path/filepath";"testing")
func TestLoadOrCreateStable(t *testing.T){root:=t.TempDir();old:=os.Getenv("XDG_CONFIG_HOME");defer os.Setenv("XDG_CONFIG_HOME",old);_ = os.Setenv("XDG_CONFIG_HOME",root);a,err:=LoadOrCreate();if err!=nil{t.Fatal(err)};b,err:=LoadOrCreate();if err!=nil{t.Fatal(err)};if a!=b{t.Fatalf("identity changed: %q != %q",a,b)};if _,err:=os.Stat(filepath.Join(root,"cmd-chat","identity"));err!=nil{t.Fatal(err)}}
