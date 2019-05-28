package org.torproject.android.sample;

import android.app.Application;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import com.jrummyapps.android.shell.CommandResult;
import com.jrummyapps.android.shell.Shell;

import org.torproject.android.binary.TorResourceInstaller;
import org.torproject.android.binary.TorServiceConstants;

import java.io.File;
import java.io.IOException;

public class sampleTorActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sample_tor);

        try {
            TorResourceInstaller torResourceInstaller = new TorResourceInstaller(this,getFilesDir());

            File fileTorBin = torResourceInstaller.installResources(); // /data/app/org.torproject.android.sample-psWAs03vUHB8gUpqLyAd8A==/lib/arm64/tor.so
            File fileTorRc = torResourceInstaller.getTorrcFile(); // /data/user/0/org.torproject.android.sample/files/torrc

            boolean success = fileTorBin != null && fileTorBin.canExecute();

            String message = "Tor install success? " + success;

            ((TextView)findViewById(R.id.lblStatus)).setText(message);

            if (success)
            {
                boolean bRet = runTorShellCmd (fileTorBin, fileTorRc);
                logNotice("runTorShellCmd returns " + bRet);
            }


        } catch (IOException e) {
            e.printStackTrace();
            logNotice(e.getMessage());

        } catch (Exception e) {
            e.printStackTrace();
            logNotice(e.getMessage());
        }
    }

    public void logNotice (String notice)
    {
        ((TextView)findViewById(R.id.lblStatus)).setText(notice);
    }

    public void logNotice (String notice, Exception e)
    {
        ((TextView)findViewById(R.id.lblStatus)).setText(notice);
        Log.e("SampleTor","error occurred",e);
    }

    public void doTorThings ()
    {
        //please see this project: https://github.com/thaliproject/Tor_Onion_Proxy_Library/
    }

    private boolean runTorShellCmd(File fileTor, File fileTorrc) throws Exception
    {
        File appCacheHome = getDir(SampleTorServiceConstants.DIRECTORY_TOR_DATA,Application.MODE_PRIVATE);

        boolean result = true;
        if (!fileTorrc.exists())
        {
            logNotice("torrc not installed: " + fileTorrc.getCanonicalPath());
            return false;
        }
        // torCmdString = /data/app/org.torproject.android.sample-psWAs03vUHB8gUpqLyAd8A==/lib/arm64/tor.so DataDirectory /data/data/org.torproject.android.sample/app_data --defaults-torrc /data/user/0/org.torproject.android.sample/files/torrc
        String torCmdString = fileTor.getCanonicalPath() // /data/app/org.torproject.android.sample-psWAs03vUHB8gUpqLyAd8A==/lib/arm64/tor.so
                + " DataDirectory " + appCacheHome.getCanonicalPath() // /data/user/0/org.torproject.android.sample/app_data
                + " --defaults-torrc " + fileTorrc; // /data/user/0/org.torproject.android.sample/files/torrc

        int exitCode = -1;

        try {
            exitCode = exec(torCmdString + " --verify-config", true);
        }
        catch (Exception e)
        {
            logNotice("Tor configuration did not verify: " + e.getMessage(),e);
            return false;
        }

        try {
            exitCode = exec(torCmdString, true);
        }
        catch (Exception e)
        {
            logNotice("Tor was unable to start: " + e.getMessage(),e);
            return false;
        }

        if (exitCode != 0)
        {
            logNotice("Tor did not start. Exit:" + exitCode);
            return false;
        }


        return result;
    }


    private int exec (String cmd, boolean wait) throws Exception
    {
        CommandResult shellResult = Shell.run(cmd); // cmd = /data/app/org.torproject.android.sample-LISG2mJ95lsyLpfhtMxEGg==/lib/arm64/tor.so DataDirectory /data/data/org.torproject.android.sample/app_data --defaults-torrc /data/user/0/org.torproject.android.sample/files/torrc --verify-config


        Log.d("Tor", "CMD: " + cmd + " ; shellResult.isSuccessful()=" + shellResult.isSuccessful());
        Log.d("Tor", "shellResult = \n" + shellResult);
        /*
         * cmd1 = /data/app/org.torproject.android.sample-LISG2mJ95lsyLpfhtMxEGg==/lib/arm64/tor.so DataDirectory /data/data/org.torproject.android.sample/app_data --defaults-torrc /data/user/0/org.torproject.android.sample/files/torrc --verify-config
         * shellResult1 =
         *      May 28 14:11:50.871 [notice] Tor 0.3.5.8 (git-5030edfb534245ed) running on Linux with Libevent 2.1.7-beta, OpenSSL 1.0.2p, Zlib 1.2.8, Liblzma 5.2.3, and Libzstd 1.3.2.
         *      May 28 14:11:50.872 [notice] Tor can't help you if you use it wrong! Learn how to be safe at https://www.torproject.org/download/download#warning
         *      May 28 14:11:50.872 [notice] Read configuration file "/data/user/0/org.torproject.android.sample/files/torrc".
         *      May 28 14:11:50.872 [warn] Couldn't find $HOME environment variable while expanding "~/.torrc"; defaulting to "".
         *      May 28 14:11:50.872 [notice] Configuration file "/usr/local/etc/tor/torrc" not present, using reasonable defaults.
         *      Configuration was valid
         *
         * cmd2 = /data/app/org.torproject.android.sample-LISG2mJ95lsyLpfhtMxEGg==/lib/arm64/tor.so DataDirectory /data/data/org.torproject.android.sample/app_data --defaults-torrc /data/user/0/org.torproject.android.sample/files/torrc
         * shellResult2 =
         *      May 28 14:17:30.555 [notice] Tor 0.3.5.8 (git-5030edfb534245ed) running on Linux with Libevent 2.1.7-beta, OpenSSL 1.0.2p, Zlib 1.2.8, Liblzma 5.2.3, and Libzstd 1.3.2.
         *      May 28 14:17:30.556 [notice] Tor can't help you if you use it wrong! Learn how to be safe at https://www.torproject.org/download/download#warning
         *      May 28 14:17:30.556 [notice] Read configuration file "/data/user/0/org.torproject.android.sample/files/torrc".
         *      May 28 14:17:30.556 [warn] Couldn't find $HOME environment variable while expanding "~/.torrc"; defaulting to "".
         *      May 28 14:17:30.556 [notice] Configuration file "/usr/local/etc/tor/torrc" not present, using reasonable defaults.
         *      May 28 14:17:30.563 [notice] Opening Control listener on 127.0.0.1:0
         *      May 28 14:17:30.564 [notice] Control listener listening on port 41933.
         *      May 28 14:17:30.564 [notice] Opened Control listener on 127.0.0.1:0
         *      May 28 14:17:30.564 [notice] DisableNetwork is set. Tor will not make or accept non-control network connections. Shutting down all existing connections.
         *
         */
        if (!shellResult.isSuccessful()) {
            throw new Exception("Error: " + shellResult.exitCode + " ERR=" + shellResult.getStderr() + " OUT=" + shellResult.getStdout());
        }

        return shellResult.exitCode;
    }
}
