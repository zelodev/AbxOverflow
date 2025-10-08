package com.example.abxoverflow;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.Toast;

import java.io.IOException;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    public void doStage1(View view) throws IOException {
        Main.stage1(this);
        Toast.makeText(this, R.string.done_toast, Toast.LENGTH_SHORT).show();
    }

    public void doStage2(View view) throws Exception {
        Main.stage2(this);
        Toast.makeText(this, R.string.done_toast, Toast.LENGTH_SHORT).show();
    }

    public void doCrash(View view) throws IOException {
        Main.crashSystemServer();
    }

    public void doEverything(View view) throws Exception {
        RebootBackgroundRunner.start(this);
        Main.stage1(this);
        Thread.sleep(1000);
        Main.crashSystemServer();
    }
}