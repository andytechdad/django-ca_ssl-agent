package main

import (
  "os"
	"runtime"
  
  agent "github.com/devopsmakers/django-ca_ssl-agent/agent"
  jww "github.com/spf13/jwalterweatherman"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
  agent.Execute()

	if jww.LogCountForLevelsGreaterThanorEqualTo(jww.LevelError) > 0 {
		os.Exit(-1)
	}
}
