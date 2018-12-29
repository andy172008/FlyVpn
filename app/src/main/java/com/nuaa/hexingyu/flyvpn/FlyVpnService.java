package com.nuaa.hexingyu.flyvpn;

import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.util.Pair;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.net.FileNameMap;
import java.util.concurrent.atomic.AtomicReference;

public class FlyVpnService extends VpnService implements Handler.Callback {

    public Handler mHandler;

    //ParcelFileDescriptor是可以用于进程间Binder通信的FileDescriptor。支持stream 写入和stream 读出
    private static class Connection extends Pair<Thread, ParcelFileDescriptor> {
        public Connection(Thread thread, ParcelFileDescriptor pfd) {
            super(thread, pfd);
        }
    }

    //AtomicReference提供了引用变量的读写原子性操作
    private final AtomicReference<Connection> mConnection = new AtomicReference<>();

    //用于处理非即时性的intent，用于后台消息提示
    private PendingIntent mConfigureIntent;


    @Override
    public void onCreate() {
        //用于发送与处理信息
        if(mHandler == null) {
            mHandler = new Handler(this);
        }


        //FLAG_UPDATE_CURRENT:如果PendingIntent已经存在，保留它并且只替换它的extra数据
        mConfigureIntent = PendingIntent.getActivity(this, 0,
                new Intent(this, FlyVpnActivity.class), PendingIntent.FLAG_UPDATE_CURRENT);


    }
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {

        if(intent.getAction().equals(FlyVpnActivity.IntentIsC)) {

            connect();

            //采用标准的重新启动程序
            return START_STICKY;
        }
        else if(intent.getAction().equals(FlyVpnActivity.IntentIsD)) {

            disconnect();

            //适用于处理特殊操作和命令的Service，当操作或命令执行完后，Service会调用stopSelf()方式终止自己
            return START_NOT_STICKY;
        }
        else {
            //怎么会跳到这一步来呢？
            return START_NOT_STICKY;
        }

    }

    @Override
    public void onDestroy() {

        disconnect();
    }


    @Override
    public boolean handleMessage(Message message) {

        Toast.makeText(this, message.what, Toast.LENGTH_SHORT).show();
        //如果不是断开连接，就把状态栏的系统通知设置上
        if (message.what != R.string.disconnected) {
            updateForegroundNotification(message.what);
        }

        return true;
    }

    private void connect() {

        //设置上方的消息提示
        updateForegroundNotification(R.string.connecting);
        //设置弹出消息
        mHandler.sendEmptyMessage(R.string.connecting);


        //service难以使用findViewById
        //创建SharedPreferences对象，依照标识符寻找是否有已存在的对象，若没有则创建一个新的对象
        final SharedPreferences prefs = getSharedPreferences(FlyVpnActivity.SPName, MODE_PRIVATE);

        final String ip = prefs.getString(FlyVpnActivity.SPIp, "");
        final int port = Integer.parseInt(prefs.getString(FlyVpnActivity.SPPort, "8000"));
        final byte[] key = prefs.getString(FlyVpnActivity.SPKey, "").getBytes();


        //启动vpn连接
        FlyVpnConnection flyConnect = new FlyVpnConnection(this,ip,port,key);
        final Thread thread = new Thread(flyConnect);

        //重写类的某些方法，成为一个新的类然后直接当作匿名内部类使用，实例一个新的对象
        flyConnect.setOnEstablishListener(new FlyVpnConnection.OnEstablishListener() {
            public void onEstablish(ParcelFileDescriptor tunInterface) {

                mHandler.sendEmptyMessage(R.string.connected);
                setConnection(new Connection(thread, tunInterface));
            }
        });

        //线程开始
        thread.start();

    }

    private void disconnect() {

        mHandler.sendEmptyMessage(R.string.disconnected);
        setConnection(null);
        stopForeground(true);
    }



    private void setConnection(final Connection connection) {
        final Connection oldConnection = mConnection.getAndSet(connection);
        if (oldConnection != null) {
            try {
                //将老线程中断，将老文件描述符关闭
                oldConnection.first.interrupt();
                oldConnection.second.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }



    //TODO 在api 26(Android 8.0)之后，这条函数需要进行修改，需要使用带有通知渠道的方法
    //但我们的程序是面向api 24(Android 7.0)写的，暂时不用担心这个问题
    private void updateForegroundNotification(final int message) {

        startForeground(1, new Notification.Builder(this)
                .setSmallIcon(R.drawable.ic_send_black_24dp)
                .setContentText(getString(message))
                .setContentIntent(mConfigureIntent)
                .build());
    }
}
