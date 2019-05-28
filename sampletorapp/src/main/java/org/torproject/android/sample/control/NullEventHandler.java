// Copyright 2005 Nick Mathewson, Roger Dingledine
// See LICENSE file for copying information
package org.torproject.android.sample.control;

/**
 * Implementation of EventHandler that ignores all events.  Useful
 * when you only want to override one method.
 */
public class NullEventHandler implements EventHandler {
    public void circuitStatus(String status, String circID, String path) {}
    public void streamStatus(String status, String streamID, String target) {}
    public void orConnStatus(String status, String orName) {}
    public void bandwidthUsed(long read, long written) {}
    public void newDescriptors(java.util.List<String> orList) {}
    public void message(String severity, String msg) {}
    public void hiddenServiceEvent(String action, String msg) {}
    public void hiddenServiceFailedEvent(String reason, String msg) {}
    public void hiddenServiceDescriptor(String descriptorId, String descriptor, String msg) {}
    public void unrecognized(String type, String msg) {}
}

