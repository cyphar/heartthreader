/* heartthreader: mass, multithreaded testing for servers against Heartbleed (CVE-2014-0160)
 * Copyright (C) 2014, Cyphar All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package main

import (
	"os"
	"io"
	"bufio"
	"strings"
	"sync"
	"fmt"
	"flag"
	"time"

	tls "github.com/titanous/heartbleeder/tls"
)

type Server struct {
	Host string
	Vulnerable bool
}

const LICENSE = "heartthreader: mass, multithreaded testing for servers against Heartbleed (CVE-2014-0160)\n" +
	"Copyright (C) 2014, Cyphar All rights reserved.\n" +
	"\n" +
	"Redistribution and use in source and binary forms, with or without\n" +
	"modification, are permitted provided that the following conditions are met:\n" +
	"\n" +
	"1. Redistributions of source code must retain the above copyright notice,\n" +
	"   this list of conditions and the following disclaimer.\n" +
	"\n" +
	"2. Redistributions in binary form must reproduce the above copyright notice,\n" +
	"   this list of conditions and the following disclaimer in the documentation\n" +
	"   and/or other materials provided with the distribution.\n" +
	"\n" +
	"3. Neither the name of the copyright holder nor the names of its contributors\n" +
	"   may be used to endorse or promote products derived from this software without\n" +
	"   specific prior written permission.\n" +
	"\n" +
	"THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\"\n" +
	"AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n" +
	"IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE\n" +
	"DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE\n" +
	"FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL\n" +
	"DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR\n" +
	"SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER\n" +
	"CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,\n" +
	"OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE\n" +
	"USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"

var Config struct {
	NumThreads int
}

func FixLine(line string) string {
	if strings.HasSuffix(line, "\n") {
		l := len(line)
		line = line[:l-1]
	}

	if !strings.Contains(line, ":") {
		line = line + ":443"
	}

	return line
}

func YieldTargets(done <-chan struct{}, files []string) <-chan string {
	hosts := make(chan string)

	go func() {
		defer close(hosts)
		for _, file := range files {
			f, err := os.Open(file)
			defer f.Close()

			if err != nil {
				fmt.Fprintf(os.Stderr, "E: %s\n", err.Error())
				continue
			}

			bf := bufio.NewReader(f)

			var line string
			for line, err = bf.ReadString('\n'); err == nil; line, err = bf.ReadString('\n') {
				host := FixLine(line)
				select {
					case hosts <- host:
					case <-done:
						fmt.Fprintf(os.Stderr, "I: yielding canceled\n")
						return
				}
			}

			f.Close()
		}
	}()

	return hosts
}

func DigestTarget(done <-chan struct{}, hosts <-chan string, c chan<- Server) {
	for host := range hosts {
		wait_err := func(conn *tls.Conn, ch chan<- error) {
			var err error

			err = conn.WriteHeartbeat(32, nil)
			_, _, err = conn.ReadHeartbeat()

			ch <- err
		}

		conn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
		defer conn.Close()

		if err != nil {
			fmt.Fprintf(os.Stderr, "E: %s\n", err.Error())
			continue
		}

		quit := time.After(10 * time.Second)
		ech := make(chan error)

		go wait_err(conn, ech)

		srv := Server{host, false}

		select {
			case err = <-ech:
				switch err {
					case nil:
						// VULNERABLE!!
						srv.Vulnerable = true
					case tls.ErrNoHeartbeat:
					default:
				}
			case <-quit:
			case <-done:
				fmt.Fprintf(os.Stderr, "I: digest of %s canceled\n", host)
				return
		}

		select {
			case c <- srv:
			case <-done:
				fmt.Fprintf(os.Stderr, "I: digest of %s canceled\n", host)
				return
		}

		conn.Close()
	}
}

func DigestAll(files []string, out chan<- Server) {
	servers := make(chan Server)
	done := make(chan struct{})
	defer close(done)

	hosts := YieldTargets(done, files)

	var wg sync.WaitGroup
	wg.Add(Config.NumThreads)

	for i := 0; i < Config.NumThreads; i++ {
		go func() {
			DigestTarget(done, hosts, servers)
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(servers)
	}()

	for server := range servers {
		out <- server
	}
}

func License() {
	fmt.Printf(LICENSE)
}

func Help(out io.Writer) {
	fmt.Fprintf(out, "Usage: %s [opts] hostfile[s]\n\n", os.Args[0])
	fmt.Fprintf(out, "Flags for %s:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var (
		o_threads = flag.Int("threads", 20, "Specify the number of threads to use when scanning the input files.")

		o_license = flag.Bool("license", false, "Show the license text.")
		o_help    = flag.Bool("help", false, "Show this help page.")
	)

	flag.Usage = func() {
		Help(os.Stderr)
	}

	flag.Parse()

	/* set configs */
	Config.NumThreads = *o_threads

	if *o_license {
		License()
		os.Exit(0)
	}

	if *o_help {
		Help(os.Stdout)
		os.Exit(0)
	}

	if len(flag.Args()) < 1 {
		Help(os.Stderr)
		os.Exit(2)
	}

	servers := make(chan Server)
	go DigestAll(flag.Args(), servers)

	for server := range servers {
		if server.Vulnerable {
			fmt.Printf("V: %s\n", server.Host)
		} else {
			fmt.Printf("N: %s\n", server.Host)
		}
	}
}
