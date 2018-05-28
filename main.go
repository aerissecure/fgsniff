package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/bgentry/speakeasy"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

/*
Example output
3.021795 10.10.0.100.42066 -> 10.10.0.1.22: ack 2725452283
0x0000	 704c a55b 64e0 5404 a61b b3dd 0800 4510	pL.[d.T.......E.
0x0010	 0034 518e 4000 4006 d4ad 0a0a 0064 0a0a	.4Q.@.@......d..
0x0020	 0001 a452 0016 f69b 908d a273 19fb 8010	...R.......s....
0x0030	 1a8b 67b8 0000 0101 080a 3e36 f642 081d	..g.......>6.B..
0x0040	 bb6a                                   	.j

TODO:
- graceful shutdown
    - get the stats sent from the fg on shutdown:
			^C
			66 packets received by filter
			0 packets dropped by kernel
- code organization
*/

// decodeSniff reads input produced by the fortigate sniffer
func decodeSniff(r io.Reader, w io.Writer) error {
	snaplen := 3000

	pw := pcapgo.NewWriter(w)
	pw.WriteFileHeader(uint32(snaplen), layers.LinkTypeEthernet)
	// ignoring error until figure out how calling and error returns will work in goroutine

	scanner := bufio.NewScanner(r)
	buf := make([]byte, snaplen, snaplen)
	length := 0

	for scanner.Scan() {
		// verbose:
		// fmt.Println("debug:", scanner.Text())
		if strings.HasPrefix(scanner.Text(), "0x0000") {
			length = 0
		}
		if strings.HasPrefix(scanner.Text(), "0x") {
			fields := strings.Split(scanner.Text(), "\t")
			hexStr := strings.Replace(fields[1], " ", "", -1)
			decoded, err := hex.DecodeString(hexStr)
			if err != nil {
				fmt.Printf("error hex decoding string %q: %v\n", hexStr, err)
				continue
			}
			for _, b := range decoded {
				buf[length] = b
				length++
			}
		}
		if scanner.Text() == "" {
			ci := gopacket.CaptureInfo{
				CaptureLength: length,
				Length:        length, // actual packet size, these won't be the same if i truncate packets myself
			}
			pw.WritePacket(ci, buf[:length])
			// flush it!
			// verbose:
			// fmt.Println("flushed buf:\n", buf[:length])
			length = 0
		}
	}
	return nil
}

func main() {
	userP := flag.String("u", "admin", "username")
	addrP := flag.String("a", "", "address of Fortigate")
	portP := flag.String("p", "22", "remote port")
	fileP := flag.String("o", "fgsniff.pcap", "output file")
	ifceP := flag.String("i", "any", "fortigate interface to sniff. default sniffs all.")
	fltrP := flag.String("f", "none", "packet filter using fortigate filtering syntax.\nFor example, to print UDP 1812 traffic between forti1 and either forti2\nor forti3: 'udp and port 1812 and host forti1 and ( forti2 or forti3 )'")
	limtP := flag.Int("c", 0, "sniff until the packet count is reached")
	vdomP := flag.String("d", "", "vdom")

	verbP := flag.Bool("v", false, "verbose")
	flag.Parse()
	if *addrP == "" {
		fmt.Println("-a is required")
		os.Exit(1)
	}

	pass, err := speakeasy.Ask("password:")
	if err != nil {
		fmt.Println("error getting password:", err)
		os.Exit(1)
	}

	sshConfig := &ssh.ClientConfig{
		User: *userP,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", *addrP+":"+*portP, sshConfig)
	if err != nil {
		fmt.Printf("Failed to dial: %s\n", err)
		os.Exit(1)
	}

	session, err := client.NewSession()
	if err != nil {
		fmt.Printf("Failed to create session: %s\n", err)
		os.Exit(1)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		session.Close()
		fmt.Printf("request for pseudo terminal failed: %s\n", err)
		os.Exit(1)
	}

	// read initial commands and then send the rest to the packet file

	f, err := os.Create(*fileP)
	if err != nil {
		fmt.Printf("unable to open %s for writing\n", *fileP)
		os.Exit(1)
	}
	defer f.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		fmt.Printf("Unable to setup stdout for session: %v\n", err)
		os.Exit(1)
	}

	// go io.Copy(f, stdout)
	go decodeSniff(stdout, f)

	cnt := ""
	if *limtP > 0 {
		cnt = fmt.Sprintf("%d", *limtP)
	}

	cmd := fmt.Sprintf("diagnose sniffer packet %s %q 3 %s", *ifceP, *fltrP, cnt)
	if *vdomP != "" {
		cmd = fmt.Sprintf("config vdom\n edit %s\n diagnose sniffer packet %s %q 3 %s", *vdomP, *ifceP, *fltrP, cnt)
	}

	if *verbP {
		fmt.Printf("running command: %s\n", cmd)
	}
	err = session.Run(cmd)
	if err != nil {
		fmt.Println("error running command:", err)
		os.Exit(1)
	}
	// keeps running until cmd session.Run returns
}
