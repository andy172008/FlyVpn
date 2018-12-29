package com.nuaa.hexingyu.flyvpn;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

public class FlyVpnActivity extends Activity {

    //为SharedPreferences对象创建一些字符串,做为标识符
    static String SPName = "SPName";
    static String SPIp = "SPIp";
    static String SPPort = "SPPort";
    static String SPKey = "SPKey";


    //为传递到Service的intent创建一些字符串，做为标识符
    static String IntentIsC = "connect";
    static String IntentIsD = "disconnect";


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_fly_vpn);

        //获取文本框的ID
        final TextView TVIp = findViewById(R.id.ip);
        final TextView TVPort = findViewById(R.id.port);
        final TextView TVKey = findViewById(R.id.key);

        //创建SharedPreferences对象，依照标识符寻找是否有已存在的对象，若没有则创建一个新的对象
        final SharedPreferences prefs = getSharedPreferences(SPName, MODE_PRIVATE);

        //将上次输入的内容加载进文本框
        TVIp.setText(prefs.getString(SPIp,""));
        TVPort.setText(prefs.getString(SPPort,""));
        TVKey.setText(prefs.getString(SPKey,""));

        //监听"连接"按钮
        findViewById(R.id.connect).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //先将输入的信息储存进SharedPreferences对象中
                prefs.edit()
                        .putString(SPIp, TVIp.getText().toString())
                        .putString(SPPort, TVPort.getText().toString())
                        .putString(SPKey, TVKey.getText().toString())
                        .apply();

                //检查系统中是否已经存在一个vpn连接了
                Intent intent = VpnService.prepare(FlyVpnActivity.this);
                //如果当前不存在一个vpn连接，或这已存在的vpn连接不是本程序建立的，prepare返回intent
                if (intent != null) {
                    //弹出窗口询问用户是否确认
                    startActivityForResult(intent, 0);
                }
                //如果当前系统中有vpn连接，而且此连接是由本程序建立的，prepare会返回null
                else {
                    onActivityResult(0, RESULT_OK, null);
                }

            }
        });

        //监听"断开"按钮
        findViewById(R.id.disconnect).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent(FlyVpnActivity.this,FlyVpnService.class);

                //设立"连接"标识符后启动Service
                intent.setAction(IntentIsD);
                startService(intent);
            }
        });

    }

    @Override
    protected void onActivityResult(int request, int result, Intent data){
        if (result == RESULT_OK) {
            Intent intent = new Intent(FlyVpnActivity.this,FlyVpnService.class);

            //设立"连接"标识符后启动Service
            intent.setAction(IntentIsC);
            startService(intent);
        }
    }
}
