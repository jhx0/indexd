package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

var isDebug = false

const prgName = "indexd"
const prgVersion = "0.1"

const helpMsg = `
USAGE: indexd [ -v | -h ]

	-v		show version information
	-h		show this help message
	-d		turn on debugging

Copyright (2018) Julian "jhx" Weber (jhx0x00@gmail.com)
If there are any suggestions or in general feedback, send
me a mail to the given address above. enjoy! :^)
`

var logfile os.File

const configPath = "/etc/indexd/config.json"

type indexdConfig struct {
	IndexdDirectory string   `json:"indexd_directory"`
	ACL             []string `json:"acl"`
	Address         string   `json:"address"`
	Port            string   `json:"port"`
	Logfile         string   `json:"logfile"`
	Cert            string   `json:"cert"`
	Key             string   `json:"key"`
}

func (addr indexdConfig) getAddrPair() string { return addr.Address + ":" + addr.Port }

var listing string
var conf indexdConfig

func clear(s *string) {
	*s = ""
}

func checkError(function, message string, err error) {
	if err != nil {
		logger(function, message)
		die(function, err.Error())
	}
}

func logger(messages ...string) {
	lstr := ""

	lstr += "Indexd: "
	for _, m := range messages {
		lstr += m
	}

	log.Println(lstr)
}

func server() {
	debug("server", "Server PID", strconv.Itoa(os.Getpid()))

	logger("Indexd service started.")

	debug("server", "Cert/Key location:", conf.Cert, "-", conf.Key)

	cert, err := tls.LoadX509KeyPair(conf.Cert, conf.Key)
	checkError("server() LoadX509KeyPair", "Certificate error", err)

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	server, err := tls.Listen("tcp", conf.Address+":"+conf.Port, tlsConfig)
	checkError("server() Listen", "Cannot listen", err)

	defer server.Close()

	for {
		client, err := server.Accept()
		if err != nil {
			logger("server() Accept", err.Error())
			continue
		}

		messages := make(chan string)

		go handleClient(client, messages)

		msg := <-messages

		debug("server", "Messages received:", msg)
	}
}

func handleClient(client net.Conn, msg chan string) {
	defer client.Close()

	logger("handleClient", ": ", "Client from ip/port ->", client.RemoteAddr().String())

	isAllowed := false

	for _, val := range conf.ACL {
		aclAddr := strings.Split(val, ":")
		clientAddr := strings.Split(client.RemoteAddr().String(), ":")

		if aclAddr[0] == clientAddr[0] {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		logger("Denied connection from", client.RemoteAddr().String())
		client.Close()
		return
	}

	msg <- "Sending Index to client"
	sendIndex(client)

	clear(&listing)
}

func sendIndex(c net.Conn) {
	defer c.Close()

	getListing()

	_, err := io.WriteString(c, listing)
	if err != nil {
		logger("sendIndex() WriteString", err.Error())
		return
	}
}

func getListing() {
	filepath.Walk(conf.IndexdDirectory, do)
}

func do(path string, info os.FileInfo, _ error) error {
	listing += path + "\n"
	return nil
}

func parseConfig() {
	buf, readErr := ioutil.ReadFile(configPath)
	checkError("parseConfig() ReadFile", "ReadFile error", readErr)

	jsonErr := json.Unmarshal(buf, &conf)
	checkError("parseConfig() Unmarshal", "Unmarshal error", jsonErr)
}

func debug(function string, data ...string) {
	if !isDebug {
		return
	}

	fmt.Printf("DEBUG: %s: ", function)
	for _, d := range data {
		fmt.Printf("%s ", d)
	}
	fmt.Println()
}

func version() {
	fmt.Printf("%s version %s", prgName, prgVersion)
	os.Exit(0)
}

func help() {
	fmt.Printf("%s", helpMsg)
	os.Exit(0)
}

func die(function, message string) {
	logger("Error: ", function, ":", " ", message)
	os.Exit(1)
}

func initLogging() {
	logfile, err := os.OpenFile(conf.Logfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	checkError("initLogging() OpenFile", "OpenFile error", err)

	log.SetOutput(logfile)
}

func setup() {
	if len(os.Args) > 2 {
		help()
	}

	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "-v":
			version()
		case "-h":
			help()
		case "-d":
			isDebug = true
		default:
			help()
		}
	}

	if os.Getuid() != 0 {
		die("setup()", "Indexd needs to be run with root rights, aborting!")
	}

	parseConfig()

	initLogging()
}

func info(function, message string) {
	fmt.Printf("Info: %s: %s", function, message)
}

func sigHandler(sig chan os.Signal) {
	<-sig
	info("sigHandler", "Catched Signal, exiting!")
	os.Exit(0)
}

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go sigHandler(sig)

	setup()

	debug("main", "Dumping IndexdConfig:",
		"Directory:", conf.IndexdDirectory,
		"IP Address:", conf.Address,
		"Port:", conf.Port,
		"ACL:",
		func([]string) string {
			var aclList string
			for _, x := range conf.ACL {
				aclList += x + " "
			}
			return aclList
		}(conf.ACL))

	defer logfile.Close()

	server()

	os.Exit(0)
}
