// Copyright 2005 Nick Mathewson, Roger Dingledine
// See LICENSE file for copying information
package org.torproject.android.sample.control;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.Writer;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** A connection to a running Tor process as specified in control-spec.txt. */
public class TorControlConnection implements TorControlCommands {

    private final LinkedList<Waiter> waiters;
    private final BufferedReader input;
    private final Writer output;

    private ControlParseThread thread; // Locking: this

    private volatile EventHandler handler;
    private volatile PrintWriter debugOutput;
    private volatile IOException parseThreadException;

    static class Waiter {

        List<ReplyLine> response; // Locking: this

        synchronized List<ReplyLine> getResponse() throws InterruptedException {
            while (response == null) {
                wait();
            }
            return response;
        }

        synchronized void setResponse(List<ReplyLine> response) {
            this.response = response;
            notifyAll();
        }
    }

    static class ReplyLine {

        final String status;
        final String msg;
        final String rest;

        ReplyLine(String status, String msg, String rest) {
            this.status = status; this.msg = msg; this.rest = rest;
        }
    }

    /** Create a new TorControlConnection to communicate with Tor over
     * a given socket.  After calling this constructor, it is typical to
     * call launchThread and authenticate. */
    public TorControlConnection(Socket connection) throws IOException {
        this(connection.getInputStream(), connection.getOutputStream());
    }

    /** Create a new TorControlConnection to communicate with Tor over
     * an arbitrary pair of data streams.
     */
    public TorControlConnection(InputStream i, OutputStream o) {
        this(new InputStreamReader(i), new OutputStreamWriter(o));
    }

    public TorControlConnection(Reader i, Writer o) {
        this.output = o;
        if (i instanceof BufferedReader)
            this.input = (BufferedReader) i;
        else
            this.input = new BufferedReader(i);
        this.waiters = new LinkedList<Waiter>();
    }

    protected final void writeEscaped(String s) throws IOException {
        StringTokenizer st = new StringTokenizer(s, "\n");
        while (st.hasMoreTokens()) {
            String line = st.nextToken();
            if (line.startsWith("."))
                line = "."+line;
            if (line.endsWith("\r"))
                line += "\n";
            else
                line += "\r\n";
            if (debugOutput != null)
                debugOutput.print(">> "+line);
            output.write(line);
        }
        output.write(".\r\n");
        if (debugOutput != null)
            debugOutput.print(">> .\n");
    }

    protected static final String quote(String s) {
        StringBuffer sb = new StringBuffer("\"");
        for (int i = 0; i < s.length(); ++i) {
            char c = s.charAt(i);
            switch (c)
            {
                case '\r':
                case '\n':
                case '\\':
                case '\"':
                    sb.append('\\');
            }
            sb.append(c);
        }
        sb.append('\"');
        return sb.toString();
    }

    protected final ArrayList<ReplyLine> readReply() throws IOException {
        ArrayList<ReplyLine> reply = new ArrayList<ReplyLine>();
        char c;
        do {
            String line = input.readLine();
            if (line == null) {
                // if line is null, the end of the stream has been reached, i.e.
                // the connection to Tor has been closed!
                if (reply.isEmpty()) {
                    // nothing received so far, can exit cleanly
                    return reply;
                }
                // received half of a reply before the connection broke down
                throw new TorControlSyntaxError("Connection to Tor " +
                        " broke down while receiving reply!");
            }
            if (debugOutput != null)
                debugOutput.println("<< "+line);
            if (line.length() < 4)
                throw new TorControlSyntaxError("Line (\""+line+"\") too short");
            String status = line.substring(0,3);
            c = line.charAt(3);
            String msg = line.substring(4);
            String rest = null;
            if (c == '+') {
                StringBuffer data = new StringBuffer();
                while (true) {
                    line = input.readLine();
                    if (debugOutput != null)
                        debugOutput.print("<< "+line);
                    if (line.equals("."))
                        break;
                    else if (line.startsWith("."))
                        line = line.substring(1);
                    data.append(line).append('\n');
                }
                rest = data.toString();
            }
            reply.add(new ReplyLine(status, msg, rest));
        } while (c != ' ');

        return reply;
    }

    protected synchronized List<ReplyLine> sendAndWaitForResponse(String s,
                                                                  String rest) throws IOException {
        if(parseThreadException != null) throw parseThreadException;
        checkThread();
        Waiter w = new Waiter();
        if (debugOutput != null)
            debugOutput.print(">> "+s);
        synchronized (waiters) {
            output.write(s);
            if (rest != null)
                writeEscaped(rest);
            output.flush();
            waiters.addLast(w);
        }
        List<ReplyLine> lst;
        try {
            lst = w.getResponse();
        } catch (InterruptedException ex) {
            throw new IOException("Interrupted");
        }
        for (Iterator<ReplyLine> i = lst.iterator(); i.hasNext(); ) {
            ReplyLine c = i.next();
            if (! c.status.startsWith("2"))
                throw new TorControlError(Integer.valueOf(c.status),"Error reply: "+c.msg);
        }
        return lst;
    }

    /** Helper: decode a CMD_EVENT command and dispatch it to our
     * EventHandler (if any). */
    protected void handleEvent(ArrayList<ReplyLine> events) {
        if (handler == null)
            return;

        for (Iterator<ReplyLine> i = events.iterator(); i.hasNext(); ) {
            ReplyLine line = i.next();
            if (line.msg.startsWith("OK"))
                continue;
            int idx = line.msg.indexOf(' ');
            String tp = line.msg.substring(0, idx).toUpperCase();
            String rest = line.msg.substring(idx+1);
            if (tp.equals("CIRC")) {
                List<String> lst = Bytes.splitStr(null, rest);
                handler.circuitStatus(lst.get(1),
                        lst.get(0),
                        lst.get(1).equals("LAUNCHED")
                                || lst.size() < 3 ? ""
                                : lst.get(2));
            } else if (tp.equals("STREAM")) {
                List<String> lst = Bytes.splitStr(null, rest);
                handler.streamStatus(lst.get(1),
                        lst.get(0),
                        lst.get(3));
                // XXXX circID.
            } else if (tp.equals("ORCONN")) {
                List<String> lst = Bytes.splitStr(null, rest);
                handler.orConnStatus(lst.get(1), lst.get(0));
            } else if (tp.equals("BW")) {
                List<String> lst = Bytes.splitStr(null, rest);
                handler.bandwidthUsed(Integer.parseInt(lst.get(0)),
                        Integer.parseInt(lst.get(1)));
            } else if (tp.equals("NEWDESC")) {
                List<String> lst = Bytes.splitStr(null, rest);
                handler.newDescriptors(lst);
            } else if (tp.equals("DEBUG") ||
                    tp.equals("INFO") ||
                    tp.equals("NOTICE") ||
                    tp.equals("WARN") ||
                    tp.equals("ERR")) {
                handler.message(tp, rest);
            } else if (tp.equals("HS_DESC")) {
                List<String> lst = Bytes.splitStr(null, rest);
                Matcher matcher;
                if ("FAILED".equals(lst.get(0))) {
                    matcher = Pattern.compile("REASON=([^\\s]*)").matcher(rest);
                    handler.hiddenServiceFailedEvent(matcher.find() ? matcher.group(1) : "NO_REASON", rest);
                } else {
                    handler.hiddenServiceEvent(lst.get(0), rest);
                }
            } else if (tp.equals("HS_DESC_CONTENT")) {
                List<String> lst = Bytes.splitStr(null, rest);
                handler.hiddenServiceDescriptor(lst.get(1), lst.size() > 3 ? lst.get(3) : "NO_DESCRIPTOR", rest);
            } else {
                handler.unrecognized(tp, rest);
            }
        }
    }


    /** Sets <b>w</b> as the PrintWriter for debugging output,
     * which writes out all messages passed between Tor and the controller.
     * Outgoing messages are preceded by "\>\>" and incoming messages are preceded
     * by "\<\<"
     */
    public void setDebugging(PrintWriter w) {
        debugOutput = w;
    }

    /** Sets <b>s</b> as the PrintStream for debugging output,
     * which writes out all messages passed between Tor and the controller.
     * Outgoing messages are preceded by "\>\>" and incoming messages are preceded
     * by "\<\<"
     */
    public void setDebugging(PrintStream s) {
        debugOutput = new PrintWriter(s, true);
    }

    /** Set the EventHandler object that will be notified of any
     * events Tor delivers to this connection.  To make Tor send us
     * events, call setEvents(). */
    public void setEventHandler(EventHandler handler) {
        this.handler = handler;
    }

    /**
     * Start a thread to react to Tor's responses in the background.
     * This is necessary to handle asynchronous events and synchronous
     * responses that arrive independantly over the same socket.
     */
    public synchronized Thread launchThread(boolean daemon) {
        ControlParseThread th = new ControlParseThread();
        if (daemon)
            th.setDaemon(true);
        th.start();
        this.thread = th;
        return th;
    }

    protected class ControlParseThread extends Thread {

        public ControlParseThread() {
            setName("TorControlParser");
        }

        @Override
        public void run() {
            try {
                react();
            } catch (IOException ex) {
                parseThreadException = ex;
            }
        }
    }

    protected synchronized void checkThread() {
        if (thread == null)
            launchThread(true);
    }

    /** helper: implement the main background loop. */
    protected void react() throws IOException {
        while (true) {
            ArrayList<ReplyLine> lst = readReply();
            if (lst.isEmpty()) {
                // connection has been closed remotely! end the loop!
                return;
            }
            if ((lst.get(0)).status.startsWith("6"))
                handleEvent(lst);
            else {
                synchronized (waiters) {
                    if (!waiters.isEmpty())
                    {
                        Waiter w;
                        w = waiters.removeFirst();
                        w.setResponse(lst);
                    }
                }

            }
        }
    }

    /**
     * 3.2. RESETCONF
     *
     * Remove all settings for a given configuration option entirely, assign its
     * default value (if any), and then assign the String provided. Typically the
     * String is left empty, to simply set an option back to its default. The syntax
     * is: <br>
     * "RESETCONF" 1*(SP keyword ["=" String]) CRLF
     * <p>
     * ["=" String] is not supported (yet?)
     *
     * @param keyword
     * @throws IOException
     */
    public void resetConf(String keyword) throws IOException {
        StringBuffer b = new StringBuffer("RESETCONF");
        b.append(" ").append(keyword);
        b.append("\r\n");
        sendAndWaitForResponse(b.toString(), null);
    }

    /** Change the value of the configuration option 'key' to 'val'.
     */
    public void setConf(String key, String value) throws IOException {
        List<String> lst = new ArrayList<String>();
        lst.add(key+" "+value);
        setConf(lst);
    }

    /** Change the values of the configuration options stored in kvMap. */
    public void setConf(Map<String, String> kvMap) throws IOException {
        List<String> lst = new ArrayList<String>();
        for (Iterator<Map.Entry<String,String>> it = kvMap.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<String,String> ent = it.next();
            lst.add(ent.getKey()+" "+ent.getValue()+"\n");
        }
        setConf(lst);
    }

    /** Changes the values of the configuration options stored in
     * <b>kvList</b>.  Each list element in <b>kvList</b> is expected to be
     * String of the format "key value".
     *
     * Tor behaves as though it had just read each of the key-value pairs
     * from its configuration file.  Keywords with no corresponding values have
     * their configuration values reset to their defaults.  setConf is
     * all-or-nothing: if there is an error in any of the configuration settings,
     * Tor sets none of them.
     *
     * When a configuration option takes multiple values, or when multiple
     * configuration keys form a context-sensitive group (see getConf below), then
     * setting any of the options in a setConf command is taken to reset all of
     * the others.  For example, if two ORBindAddress values are configured, and a
     * command arrives containing a single ORBindAddress value, the new
     * command's value replaces the two old values.
     *
     * To remove all settings for a given option entirely (and go back to its
     * default value), include a String in <b>kvList</b> containing the key and no value.
     */
    public void setConf(Collection<String> kvList) throws IOException {
        if (kvList.size() == 0)
            return;
        StringBuffer b = new StringBuffer("SETCONF");
        for (Iterator<String> it = kvList.iterator(); it.hasNext(); ) {
            String kv = it.next();
            int i = kv.indexOf(' ');
            if (i == -1)
                b.append(" ").append(kv);
            b.append(" ").append(kv.substring(0,i)).append("=")
                    .append(quote(kv.substring(i+1)));
        }
        b.append("\r\n");
        sendAndWaitForResponse(b.toString(), null);
    }

    /** Try to reset the values listed in the collection 'keys' to their
     * default values.
     **/
    public void resetConf(Collection<String> keys) throws IOException {
        if (keys.size() == 0)
            return;
        StringBuffer b = new StringBuffer("RESETCONF");
        for (Iterator<String> it = keys.iterator(); it.hasNext(); ) {
            String key = it.next();
            b.append(" ").append(key);
        }
        b.append("\r\n");
        sendAndWaitForResponse(b.toString(), null);
    }

    /** Return the value of the configuration option 'key' */
    public List<ConfigEntry> getConf(String key) throws IOException {
        List<String> lst = new ArrayList<String>();
        lst.add(key);
        return getConf(lst);
    }

    /** Requests the values of the configuration variables listed in <b>keys</b>.
     * Results are returned as a list of ConfigEntry objects.
     *
     * If an option appears multiple times in the configuration, all of its
     * key-value pairs are returned in order.
     *
     * Some options are context-sensitive, and depend on other options with
     * different keywords.  These cannot be fetched directly.  Currently there
     * is only one such option: clients should use the "HiddenServiceOptions"
     * virtual keyword to get all HiddenServiceDir, HiddenServicePort,
     * HiddenServiceNodes, and HiddenServiceExcludeNodes option settings.
     */
    public List<ConfigEntry> getConf(Collection<String> keys) throws IOException {
        StringBuffer sb = new StringBuffer("GETCONF");
        for (Iterator<String> it = keys.iterator(); it.hasNext(); ) {
            String key = it.next();
            sb.append(" ").append(key);
        }
        sb.append("\r\n");
        List<ReplyLine> lst = sendAndWaitForResponse(sb.toString(), null);
        List<ConfigEntry> result = new ArrayList<ConfigEntry>();
        for (Iterator<ReplyLine> it = lst.iterator(); it.hasNext(); ) {
            String kv = (it.next()).msg;
            int idx = kv.indexOf('=');
            if (idx >= 0)
                result.add(new ConfigEntry(kv.substring(0, idx),
                        kv.substring(idx+1)));
            else
                result.add(new ConfigEntry(kv));
        }
        return result;
    }

    /** Request that the server inform the client about interesting events.
     * Each element of <b>events</b> is one of the following Strings:
     * ["CIRC" | "STREAM" | "ORCONN" | "BW" | "DEBUG" |
     *  "INFO" | "NOTICE" | "WARN" | "ERR" | "NEWDESC" | "ADDRMAP"] .
     *
     * Any events not listed in the <b>events</b> are turned off; thus, calling
     * setEvents with an empty <b>events</b> argument turns off all event reporting.
     */
    public void setEvents(List<String> events) throws IOException {
        StringBuffer sb = new StringBuffer("SETEVENTS");
        for (Iterator<String> it = events.iterator(); it.hasNext(); ) {
            sb.append(" ").append(it.next());
        }
        sb.append("\r\n");
        sendAndWaitForResponse(sb.toString(), null);
    }

    /** Authenticates the controller to the Tor server.
     *
     * By default, the current Tor implementation trusts all local users, and
     * the controller can authenticate itself by calling authenticate(new byte[0]).
     *
     * If the 'CookieAuthentication' option is true, Tor writes a "magic cookie"
     * file named "control_auth_cookie" into its data directory.  To authenticate,
     * the controller must send the contents of this file in <b>auth</b>.
     *
     * If the 'HashedControlPassword' option is set, <b>auth</b> must contain the salted
     * hash of a secret password.  The salted hash is computed according to the
     * S2K algorithm in RFC 2440 (OpenPGP), and prefixed with the s2k specifier.
     * This is then encoded in hexadecimal, prefixed by the indicator sequence
     * "16:".
     *
     * You can generate the salt of a password by calling
     *       'tor --hash-password <password>'
     * or by using the provided PasswordDigest class.
     * To authenticate under this scheme, the controller sends Tor the original
     * secret that was used to generate the password.
     */
    public void authenticate(byte[] auth) throws IOException {
        String cmd = "AUTHENTICATE " + Bytes.hex(auth) + "\r\n";
        sendAndWaitForResponse(cmd, null);
    }

    /** Instructs the server to write out its configuration options into its torrc.
     */
    public void saveConf() throws IOException {
        sendAndWaitForResponse("SAVECONF\r\n", null);
    }
/*
*
*
* https://github.com/torproject/torspec/blob/master/control-spec.txt
 * 3.26. HSFETCH
 *
 *   The syntax is:
 *     "HSFETCH" SP (HSAddress / "v" Version "-" DescId)
 *               *[SP "SERVER=" Server] CRLF
 *
 *     HSAddress = 16*Base32Character / 56*Base32Character
 *     Version = "2" / "3"
 *     DescId = 32*Base32Character
 *     Server = LongName
 *
 *   This command launches hidden service descriptor fetch(es) for the given
 *   HSAddress or DescId.
 *
 *   HSAddress can be version 2 or version 3 addresses. DescIDs can only be
 *   version 2 IDs. Version 2 addresses consist of 16*Base32Character and
 *   version 3 addresses consist of 56*Base32Character.
 *
 *   If a DescId is specified, at least one Server MUST also be provided,
 *   otherwise a 512 error is returned. If no DescId and Server(s) are specified,
 *   it behaves like a normal Tor client descriptor fetch. If one or more
 *   Server are given, they are used instead triggering a fetch on each of them
 *   in parallel.
 *
 *   The caching behavior when fetching a descriptor using this command is
 *   identical to normal Tor client behavior.
 *
 *   Details on how to compute a descriptor id (DescId) can be found in
 *   rend-spec.txt section 1.3.
 *
 *   If any values are unrecognized, a 513 error is returned and the command is
 *   stopped. On success, Tor replies "250 OK" then Tor MUST eventually follow
 *   this with both a HS_DESC and HS_DESC_CONTENT events with the results. If
 *   SERVER is specified then events are emitted for each location.
 *
 *   Examples are:
 *      C: HSFETCH v2-gezdgnbvgy3tqolbmjrwizlgm5ugs2tl
 *         SERVER=9695DFC35FFEB861329B9F1AB04C46397020CE31
 *      S: 250 OK
 *
 *      C: HSFETCH ajkhdsfuygaesfaa
 *      S: 250 OK
 *
 *      C: HSFETCH vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd
 *      S: 250 OK
 *
 *   [HSFETCH was added in Tor 0.2.7.1-alpha]
 *   [HS v3 support added 0.4.1.1-alpha]
 *
 */
    public boolean isHSAvailable(String onionurl) throws IOException {
        final List<ReplyLine> response = sendAndWaitForResponse("HSFETCH "+onionurl+"\r\n", null);
        return response.get(0).status.trim().equals("250");
    }

    /** Sends a signal from the controller to the Tor server.
     * <b>signal</b> is one of the following Strings:
     * <ul>
     * <li>"RELOAD" or "HUP" :  Reload config items, refetch directory</li>
     * <li>"SHUTDOWN" or "INT" : Controlled shutdown: if server is an OP, exit immediately.
     *     If it's an OR, close listeners and exit after 30 seconds</li>
     * <li>"DUMP" or "USR1" : Dump stats: log information about open connections and circuits</li>
     * <li>"DEBUG" or "USR2" : Debug: switch all open logs to loglevel debug</li>
     * <li>"HALT" or "TERM" : Immediate shutdown: clean up and exit now</li>
     * </ul>
     */
    public void signal(String signal) throws IOException {
        String cmd = "SIGNAL " + signal + "\r\n";
        sendAndWaitForResponse(cmd, null);
    }

    /** Send a signal to the Tor process to shut it down or halt it.
     * Does not wait for a response. */
    public void shutdownTor(String signal) throws IOException {
        String s = "SIGNAL " + signal + "\r\n";
        if (debugOutput != null)
            debugOutput.print(">> "+s);
        synchronized (waiters) {
            output.write(s);
            output.flush();
        }
    }

    /** Tells the Tor server that future SOCKS requests for connections to a set of original
     * addresses should be replaced with connections to the specified replacement
     * addresses.  Each element of <b>kvLines</b> is a String of the form
     * "old-address new-address".  This function returns the new address mapping.
     *
     * The client may decline to provide a body for the original address, and
     * instead send a special null address ("0.0.0.0" for IPv4, "::0" for IPv6, or
     * "." for hostname), signifying that the server should choose the original
     * address itself, and return that address in the reply.  The server
     * should ensure that it returns an element of address space that is unlikely
     * to be in actual use.  If there is already an address mapped to the
     * destination address, the server may reuse that mapping.
     *
     * If the original address is already mapped to a different address, the old
     * mapping is removed.  If the original address and the destination address
     * are the same, the server removes any mapping in place for the original
     * address.
     *
     * Mappings set by the controller last until the Tor process exits:
     * they never expire. If the controller wants the mapping to last only
     * a certain time, then it must explicitly un-map the address when that
     * time has elapsed.
     */
    public Map<String,String> mapAddresses(Collection<String> kvLines) throws IOException {
        StringBuffer sb = new StringBuffer("MAPADDRESS");
        for (Iterator<String> it = kvLines.iterator(); it.hasNext(); ) {
            String kv = it.next();
            int i = kv.indexOf(' ');
            sb.append(" ").append(kv.substring(0,i)).append("=")
                    .append(quote(kv.substring(i+1)));
        }
        sb.append("\r\n");
        List<ReplyLine> lst = sendAndWaitForResponse(sb.toString(), null);
        Map<String,String> result = new HashMap<String,String>();
        for (Iterator<ReplyLine> it = lst.iterator(); it.hasNext(); ) {
            String kv = (it.next()).msg;
            int idx = kv.indexOf('=');
            result.put(kv.substring(0, idx),
                    kv.substring(idx+1));
        }
        return result;
    }

    public Map<String,String> mapAddresses(Map<String,String> addresses) throws IOException {
        List<String> kvList = new ArrayList<String>();
        for (Iterator<Map.Entry<String, String>> it = addresses.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<String,String> e = it.next();
            kvList.add(e.getKey()+" "+e.getValue());
        }
        return mapAddresses(kvList);
    }

    public String mapAddress(String fromAddr, String toAddr) throws IOException {
        List<String> lst = new ArrayList<String>();
        lst.add(fromAddr+" "+toAddr+"\n");
        Map<String,String> m = mapAddresses(lst);
        return m.get(fromAddr);
    }

    /** Queries the Tor server for keyed values that are not stored in the torrc
     * configuration file.  Returns a map of keys to values.
     *
     * Recognized keys include:
     * <ul>
     * <li>"version" : The version of the server's software, including the name
     *  of the software. (example: "Tor 0.0.9.4")</li>
     * <li>"desc/id/<OR identity>" or "desc/name/<OR nickname>" : the latest server
     * descriptor for a given OR, NUL-terminated.  If no such OR is known, the
     * corresponding value is an empty string.</li>
     * <li>"network-status" : a space-separated list of all known OR identities.
     * This is in the same format as the router-status line in directories;
     * see tor-spec.txt for details.</li>
     * <li>"addr-mappings/all"</li>
     * <li>"addr-mappings/config"</li>
     * <li>"addr-mappings/cache"</li>
     * <li>"addr-mappings/control" : a space-separated list of address mappings, each
     * in the form of "from-address=to-address".  The 'config' key
     * returns those address mappings set in the configuration; the 'cache'
     * key returns the mappings in the client-side DNS cache; the 'control'
     * key returns the mappings set via the control interface; the 'all'
     * target returns the mappings set through any mechanism.</li>
     * <li>"circuit-status" : A series of lines as for a circuit status event. Each line is of the form:
     * "CircuitID CircStatus Path"</li>
     * <li>"stream-status" : A series of lines as for a stream status event.  Each is of the form:
     * "StreamID StreamStatus CircID Target"</li>
     * <li>"orconn-status" : A series of lines as for an OR connection status event.  Each is of the
     * form: "ServerID ORStatus"</li>
     * </ul>
     */
    public Map<String,String> getInfo(Collection<String> keys) throws IOException {
        StringBuffer sb = new StringBuffer("GETINFO");
        for (Iterator<String> it = keys.iterator(); it.hasNext(); ) {
            sb.append(" ").append(it.next());
        }
        sb.append("\r\n");
        List<ReplyLine> lst = sendAndWaitForResponse(sb.toString(), null);
        Map<String,String> m = new HashMap<String,String>();
        for (Iterator<ReplyLine> it = lst.iterator(); it.hasNext(); ) {
            ReplyLine line = it.next();
            int idx = line.msg.indexOf('=');
            if (idx<0)
                break;
            String k = line.msg.substring(0,idx);
            String v;
            if (line.rest != null) {
                v = line.rest;
            } else {
                v = line.msg.substring(idx+1);
            }
            m.put(k, v);
        }
        return m;
    }



    /** Return the value of the information field 'key' */
    public String getInfo(String key) throws IOException {
        List<String> lst = new ArrayList<String>();
        lst.add(key);
        Map<String,String> m = getInfo(lst);
        return  m.get(key);
    }

    /** An extendCircuit request takes one of two forms: either the <b>circID</b> is zero, in
     * which case it is a request for the server to build a new circuit according
     * to the specified path, or the <b>circID</b> is nonzero, in which case it is a
     * request for the server to extend an existing circuit with that ID according
     * to the specified <b>path</b>.
     *
     * If successful, returns the Circuit ID of the (maybe newly created) circuit.
     */
    public String extendCircuit(String circID, String path) throws IOException {
        List<ReplyLine> lst = sendAndWaitForResponse(
                "EXTENDCIRCUIT "+circID+" "+path+"\r\n", null);
        return (lst.get(0)).msg;
    }

    /** Informs the Tor server that the stream specified by <b>streamID</b> should be
     * associated with the circuit specified by <b>circID</b>.
     *
     * Each stream may be associated with
     * at most one circuit, and multiple streams may share the same circuit.
     * Streams can only be attached to completed circuits (that is, circuits that
     * have sent a circuit status "BUILT" event or are listed as built in a
     * getInfo circuit-status request).
     *
     * If <b>circID</b> is 0, responsibility for attaching the given stream is
     * returned to Tor.
     *
     * By default, Tor automatically attaches streams to
     * circuits itself, unless the configuration variable
     * "__LeaveStreamsUnattached" is set to "1".  Attempting to attach streams
     * via TC when "__LeaveStreamsUnattached" is false may cause a race between
     * Tor and the controller, as both attempt to attach streams to circuits.
     */
    public void attachStream(String streamID, String circID)
            throws IOException {
        sendAndWaitForResponse("ATTACHSTREAM "+streamID+" "+circID+"\r\n", null);
    }

    /** Tells Tor about the server descriptor in <b>desc</b>.
     *
     * The descriptor, when parsed, must contain a number of well-specified
     * fields, including fields for its nickname and identity.
     */
    // More documentation here on format of desc?
    // No need for return value?  control-spec.txt says reply is merely "250 OK" on success...
    public String postDescriptor(String desc) throws IOException {
        List<ReplyLine> lst = sendAndWaitForResponse("+POSTDESCRIPTOR\r\n", desc);
        return (lst.get(0)).msg;
    }

    /** Tells Tor to change the exit address of the stream identified by <b>streamID</b>
     * to <b>address</b>. No remapping is performed on the new provided address.
     *
     * To be sure that the modified address will be used, this event must be sent
     * after a new stream event is received, and before attaching this stream to
     * a circuit.
     */
    public void redirectStream(String streamID, String address) throws IOException {
        sendAndWaitForResponse("REDIRECTSTREAM "+streamID+" "+address+"\r\n",
                null);
    }

    /** Tells Tor to close the stream identified by <b>streamID</b>.
     * <b>reason</b> should be one of the Tor RELAY_END reasons given in tor-spec.txt, as a decimal:
     * <ul>
     * <li>1 -- REASON_MISC           (catch-all for unlisted reasons)</li>
     * <li>2 -- REASON_RESOLVEFAILED  (couldn't look up hostname)</li>
     * <li>3 -- REASON_CONNECTREFUSED (remote host refused connection)</li>
     * <li>4 -- REASON_EXITPOLICY     (OR refuses to connect to host or port)</li>
     * <li>5 -- REASON_DESTROY        (Circuit is being destroyed)</li>
     * <li>6 -- REASON_DONE           (Anonymized TCP connection was closed)</li>
     * <li>7 -- REASON_TIMEOUT        (Connection timed out, or OR timed out while connecting)</li>
     * <li>8 -- (unallocated)</li>
     * <li>9 -- REASON_HIBERNATING    (OR is temporarily hibernating)</li>
     * <li>10 -- REASON_INTERNAL       (Internal error at the OR)</li>
     * <li>11 -- REASON_RESOURCELIMIT  (OR has no resources to fulfill request)</li>
     * <li>12 -- REASON_CONNRESET      (Connection was unexpectedly reset)</li>
     * <li>13 -- REASON_TORPROTOCOL    (Sent when closing connection because of Tor protocol violations)</li>
     * </ul>
     *
     * Tor may hold the stream open for a while to flush any data that is pending.
     */
    public void closeStream(String streamID, byte reason)
            throws IOException {
        sendAndWaitForResponse("CLOSESTREAM "+streamID+" "+reason+"\r\n",null);
    }

    /** Tells Tor to close the circuit identified by <b>circID</b>.
     * If <b>ifUnused</b> is true, do not close the circuit unless it is unused.
     */
    public void closeCircuit(String circID, boolean ifUnused) throws IOException {
        sendAndWaitForResponse("CLOSECIRCUIT "+circID+
                (ifUnused?" IFUNUSED":"")+"\r\n", null);
    }

    /** Tells Tor to exit when this control connection is closed. This command
     * was added in Tor 0.2.2.28-beta.
     */
    public void takeOwnership() throws IOException {
        sendAndWaitForResponse("TAKEOWNERSHIP\r\n", null);
    }

    /** Tells Tor to forget any cached client state relating to the hidden
     * service with the given hostname (excluding the .onion extension).
     */
    public void forgetHiddenService(String hostname) throws IOException {
        sendAndWaitForResponse("FORGETHS " + hostname + "\r\n", null);
    }

    /**
     * "ADD_ONION" SP KeyType ":" KeyBlob [SP "Flags=" Flag *("," Flag)] [SP
     * "MaxStreams=" NumStreams] 1*(SP "Port=" VirtPort ["," Target]) (SP
     * "ClientAuth=" ClientName [":" ClientBlob]) CRLF
     *
     * KeyType = "NEW" / ; The server should generate a key of algorithm KeyBlob
     * "RSA1024" / ; The server should use the 1024 bit RSA key provided in as
     * KeyBlob "ED25519-V3"; The server should use the ed25519 v3 key provided in as
     * KeyBlob
     *
     * KeyBlob = "BEST" / ; The server should generate a key using the "best"
     * supported algorithm (KeyType == "NEW") "RSA1024" / ; The server should
     * generate a 1024 bit RSA key (KeyType == "NEW") "ED25519-V3"; The server
     * should generate an ed25519 private key (KeyType == "NEW") String ; A
     * serialized private key (without whitespace)
     *
     * Flag = "DiscardPK" / ; The server should not include the newly generated
     * private key as part of the response. "Detach" / ; Do not associate the newly
     * created Onion Service to the current control connection. "BasicAuth" / ;
     * Client authorization is required using the "basic" method. "NonAnonymous" /;
     * Add a non-anonymous Single Onion Service. Tor checks this flag matches its
     * configured hidden service anonymity mode. "MaxStreamsCloseCircuit"; Close the
     * circuit is the maximum streams allowed is reached.
     *
     * NumStreams = A value between 0 and 65535 which is used as the maximum streams
     * that can be attached on a rendezvous circuit. Setting it to 0 means unlimited
     * which is also the default behavior.
     *
     * VirtPort = The virtual TCP Port for the Onion Service (As in the
     * HiddenServicePort "VIRTPORT" argument).
     *
     * Target = The (optional) target for the given VirtPort (As in the optional
     * HiddenServicePort "TARGET" argument).
     *
     * ClientName = An identifier 1 to 16 characters long, using only characters in
     * A-Za-z0-9+-_ (no spaces).
     *
     * ClientBlob = Authorization data for the client, in an opaque format specific
     * to the authorization method.
     *
     * The server reply format is: "250-ServiceID=" ServiceID CRLF
     * ["250-PrivateKey=" KeyType ":" KeyBlob CRLF] ("250-ClientAuth=" ClientName
     * ":" ClientBlob CRLF) "250 OK" CRLF
     *
     * ServiceID = The Onion Service address without the trailing ".onion" suffix
     *
     * @throws IOException
     */
    public CreateHiddenServiceResult createHiddenService(Integer port) throws IOException {
        return createHiddenService(port, -1, "NEW:BEST");
    }

    public CreateHiddenServiceResult createHiddenService(Integer virtPort, Integer targetPort) throws IOException {
        return createHiddenService(virtPort, targetPort, "NEW:BEST");
    }

    /**
     * supported algorithms according to
     * https://github.com/torproject/torspec/raw/4421149986369b4f746fc02a5d78c7337fe5d4ea/control-spec.txt
     */
    private final static String[] algorithms = { "RSA1024", "ED25519-V3" };


    public CreateHiddenServiceResult createHiddenService(Integer port, String private_key) throws IOException {
        return createHiddenService(port, -1, private_key);
    }

    public CreateHiddenServiceResult createHiddenService(Integer virtPort, Integer targetPort, String private_key)
            throws IOException {

        // assemble port string
        String port = virtPort.toString();

        if (targetPort > 0)
            port += "," + targetPort;

        /*
         * we could try to decode the supplied key and somehow get its type, however, as
         * Java does not want to read PKCS1-encoded PEM without external help, we let
         * the Tor binary do the math.
         */
        List<ReplyLine> result = null;
        for (String algorithm : algorithms)
            try {
                result = sendAndWaitForResponse(
                        "ADD_ONION " + getPemPrivateKey(private_key, algorithm) + " Port=" + port + "\r\n", null);
                break;
            } catch (TorControlError e) {
                if (e.getErrorType() != 513)
                    throw new IOException(e.getMessage());
            }

        // in case result is still not properly filled, we do not know the correct
        // key type. Maybe Tor has a new key type available?
        if (null == result)
            throw new IOException("Unsupported private_key algorithm. Did Tor get a new key type for hidden services?");

        CreateHiddenServiceResult creationResult = new CreateHiddenServiceResult(result.get(0).msg.replace("ServiceID=", ""),
                private_key.contains("NEW") ? result.get(1).msg.replace("PrivateKey=", "") : private_key);

        /*
         * by asking for the service we just created, Tor is going to aquire a suitable
         * hidden service descriptor. When such a descriptor is not found in Tors local
         * cache, Tor tries to publish the descriptor or at least the onion address. The
         * nice thing about that is that a HSFETCH (i.e. what isHSAvailable does),
         * triggers HS_DESC and HS_DESC_CONTENT events when Tor gets the information.
         */
        isHSAvailable(creationResult.serviceID);

        return creationResult;
    }

    public class CreateHiddenServiceResult {
        public final String serviceID;
        public final String privateKey;

        public CreateHiddenServiceResult(String serviceID, String privateKey) throws IOException {
            this.serviceID = serviceID;

            if (privateKey.startsWith("-----BEGIN")) // we reused a key
                this.privateKey = privateKey;
            else {
                String type;
                if (privateKey.startsWith(algorithms[0])) // i.e. RSA1024
                    type = "RSA";
                else if (privateKey.startsWith(algorithms[1])) // i.e. ED25519-V3
                    type = "OPENSSH";
                else
                    throw new IOException(
                            "Unsupported private_key algorithm. Did Tor get a new key type for hidden services?");

                this.privateKey = "-----BEGIN " + type + " PRIVATE KEY-----\n"
                        + privateKey.substring(privateKey.indexOf(":") + 1) + "\n-----END " + type
                        + " PRIVATE KEY-----";
            }
        }
    }

    private String getPemPrivateKey(String keyBytes, String algorithm) {
        // we do not need to construct anything in case Tor is about to generate a key
        if (keyBytes.startsWith("NEW"))
            return keyBytes;

        // cleanup PEM artifacts
        String temp = new String(keyBytes);
        String privKeyPEM = temp.replaceAll("-----(BEGIN|END) ?[A-Z]* PRIVATE KEY-----", "");
        privKeyPEM = privKeyPEM.replaceAll("\n", "");

        // construct the key type and blob
        return algorithm + ":" + privKeyPEM;
    }

    /**
     * 3.28. DEL_ONION
     *
     * The syntax is: "DEL_ONION" SP ServiceID CRLF
     *
     * ServiceID = The Onion Service address without the trailing ".onion" suffix
     *
     * Tells the server to remove an Onion ("Hidden") Service, that was previously
     * created via an "ADD_ONION" command. It is only possible to remove Onion
     * Services that were created on the same control connection as the "DEL_ONION"
     * command, and those that belong to no control connection in particular (The
     * "Detach" flag was specified at creation).
     *
     * If the ServiceID is invalid, or is neither owned by the current control
     * connection nor a detached Onion Service, the server will return a 552.
     *
     * It is the Onion Service server application's responsibility to close existing
     * client connections if desired after the Onion Service has been removed via
     * "DEL_ONION".
     *
     * Tor replies with "250 OK" on success, or a 512 if there are an invalid number
     * of arguments, or a 552 if it doesn't recognize the ServiceID.
     *
     * [DEL_ONION was added in Tor 0.2.7.1-alpha.] [HS v3 support added
     * 0.3.3.1-alpha]
     */
    public void destroyHiddenService(String name) throws IOException {
        sendAndWaitForResponse("DEL_ONION " + name + "\r\n", null);
    }

    /**
     * 3.24. AUTHCHALLENGE
     *
     * The syntax is: "AUTHCHALLENGE" SP "SAFECOOKIE" SP ClientNonce CRLF
     *
     * ClientNonce = 2*HEXDIG / QuotedString
     *
     * This command is used to begin the authentication routine for the SAFECOOKIE
     * method of authentication.
     *
     * If the server accepts the command, the server reply format is: "250
     * AUTHCHALLENGE" SP "SERVERHASH=" ServerHash SP "SERVERNONCE=" ServerNonce CRLF
     *
     * ServerHash = 64*64HEXDIG ServerNonce = 64*64HEXDIG
     *
     * The ClientNonce, ServerHash, and ServerNonce values are encoded/decoded in
     * the same way as the argument passed to the AUTHENTICATE command. ServerNonce
     * MUST be 32 bytes long.
     *
     * ServerHash is computed as: HMAC-SHA256("Tor safe cookie authentication
     * server-to-controller hash", CookieString | ClientNonce | ServerNonce) (with
     * the HMAC key as its first argument)
     *
     * After a controller sends a successful AUTHCHALLENGE command, the next command
     * sent on the connection must be an AUTHENTICATE command, and the only
     * authentication string which that AUTHENTICATE command will accept is:
     * HMAC-SHA256("Tor safe cookie authentication controller-to-server hash",
     * CookieString | ClientNonce | ServerNonce)
     *
     * [Unlike other commands besides AUTHENTICATE, AUTHCHALLENGE may be used (but
     * only once!) before AUTHENTICATE.]
     *
     * [AUTHCHALLENGE was added in Tor 0.2.3.13-alpha.]
     *
     * @throws IOException
     */
    public AuthChallengeResult authChallenge(byte[] clientNonce) throws IOException {

        List<ReplyLine> result = sendAndWaitForResponse(
                "AUTHCHALLENGE SAFECOOKIE " + byteArrayToHexString(clientNonce) + "\r\n",
                null);

        if (!"250".equals(result.get(0).status)) {
            String error = "";
            for (ReplyLine line : result)
                error += line.status + " " + line.msg + ",";

            throw new IOException("Connection failed: " + error);
        }

        String tmp = result.get(0).msg;
        final String SERVERHASH = "SERVERHASH";

        String serverhash = tmp.substring(tmp.indexOf("=") + 1,
                tmp.indexOf(" ", tmp.indexOf(SERVERHASH) + SERVERHASH.length()));
        return new AuthChallengeResult(hexStringToByteArray(serverhash),
                hexStringToByteArray(tmp.substring(tmp.lastIndexOf("=") + 1)));
    }

    public class AuthChallengeResult {
        public final byte[] serverHash;
        public final byte[] serverNonce;

        public AuthChallengeResult(byte[] serverHash, byte[] serverNonce) {
            this.serverHash = serverHash;
            this.serverNonce = serverNonce;
        }
    }

    private static String byteArrayToHexString(byte[] b) {
        Character[] base16 = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

        String result = "";

        for (byte current : b)
            result += base16[(current & 0xFF) >> 4] + "" + base16[current & 0xF];

        return result;
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
