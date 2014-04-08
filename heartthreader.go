/* heartthreader: test large multithreaded amounts of domains against the Heartbleed vuln (CVE-2014-0160)
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
	"fmt"
	"os"
	"time"
	"bufio"
	"strings"

	"github.com/titanous/heartbleeder/tls"
)

func wait_err(conn *tls.Conn, ch chan error) {
	_, _, err := conn.Heartbeat(32, nil)
	ch <- err
}

func check_host(host string) {
	conn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})

	if err != nil {
		fmt.Printf("ERR: %s\n", err.Error())
		return
	}

	quit := time.After(10 * time.Second)
	ech := make(chan error)

	go wait_err(conn, ech)

	select {
		case err = <-ech:
			switch err {
				case nil:
					// VULNERABLE!!
					fmt.Printf("%s\n", host)
				case tls.ErrNoHeartbeat:
				default:
			}
		case <-quit:
			return
	}
}

func fix_line(line string) string {
	if strings.HasSuffix(line, "\n") {
		l := len(line)
		line = line[:l-1]
	}

	if !strings.Contains(line, ":") {
		line = line + ":443"
	}

	return line
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s hostfile[s]\n", os.Args[0])
		os.Exit(2)
	}

	for _, file := range os.Args[1:] {
		f, err := os.Open(file)

		if err != nil {
			fmt.Printf("ERR: %s\n", err.Error())
			continue
		}

		bf := bufio.NewReader(f)

		var line string
		for line, err = bf.ReadString('\n'); err == nil; line, err = bf.ReadString('\n') {
			host := fix_line(line)
			go check_host(host)
		}
	}

	/* block the night away */
	select {}
}
