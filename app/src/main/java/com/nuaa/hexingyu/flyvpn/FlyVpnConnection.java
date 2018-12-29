package com.nuaa.hexingyu.flyvpn;

import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

import static java.nio.charset.StandardCharsets.US_ASCII;

public class FlyVpnConnection implements Runnable{

    //这个接口用于在Service中设置当前线程和连接
    public interface OnEstablishListener {
        void onEstablish(ParcelFileDescriptor tunInterface);
    }

    //设置最大传输单元MTU
    private static final int MAX_PACKET_SIZE = Short.MAX_VALUE;
    //失去连接后等待的时间
    private static final long RECONNECT_WAIT_MS = TimeUnit.SECONDS.toMillis(3);
    //如果没有流量，存活的时间
    private static final long KEEPALIVE_INTERVAL_MS = TimeUnit.SECONDS.toMillis(15);
    //没有收到服务器响应时，等待的时间
    private static final long RECEIVE_TIMEOUT_MS = TimeUnit.SECONDS.toMillis(20);
    //在没有从内部接口或外部接口获得数据后，线程沉睡的时间
    private static final long IDLE_INTERVAL_MS = TimeUnit.MILLISECONDS.toMillis(100);
    //在握手完成和故障出现前，要等待的周期数
    private static final int MAX_HANDSHAKE_ATTEMPTS = 50;


    private final VpnService mService;
    private final String mIp;
    private final int mPort;
    private final byte[] mKey;
    //服务器应答
    private String serverAnswer;

    private OnEstablishListener mOnEstablishListener;

    //构造函数，对一些基本参数进行设置
    public FlyVpnConnection(final VpnService service,final String ip,final int port,final byte[] key){
        mService = service;
        mIp = ip;
        mPort = port;
        mKey = key;
    }


    //在Service中使用匿名共享类进行赋值，本线程中可用mOnEstablishListener对Service中的参数进行设置
    public void setOnEstablishListener(OnEstablishListener listener) {
        mOnEstablishListener = listener;
    }





    //service调用start函数后，线程从这里开始执行
    @Override
    public void run() {

        //根据ip地址和端口号创建套接字地址
        final SocketAddress serverAddress = new InetSocketAddress(mIp, mPort);

        //尝试着创建隧道
        for (int attempt = 0; attempt < 3; ++attempt) {
            try {
                if (connectBody(serverAddress)) {
                    attempt = 0;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

            //连接不上，这时候只能让线程睡一会儿了
            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

    }

    //vpn连接的主体部分
    private boolean connectBody(SocketAddress server) throws IOException {
        //判断连接是否成功的标识符
        boolean connected = false;

        //对内的接口，用于获取其他app的数据
        ParcelFileDescriptor insideInterface;
        //创建对外的隧道，用于向服务器发送数据
        //创建一个DatagramChannel做为VPN隧道,DatagramChannel 是一个能收发 UDP 包的通道
        DatagramChannel tunnel = DatagramChannel.open();

        try{
            //保护VPN连接所使用的socket.保护后，通过这个socket发送的数据，将直接进入到底层网络（物理网络），流量
            //不会通过vpn连接转发
            if (!mService.protect(tunnel.socket())) {
                throw new IllegalStateException("Cannot protect the tunnel");
            }

            //设置服务器权限
            tunnel.connect(server);
            //将隧道设置为非阻塞模式
            tunnel.configureBlocking(false);
            //尝试获取对外的接口
            if(getOutsideInterface(tunnel)) {

                //若成功与服务器建立起连接，则获取对内的接口
                insideInterface = getInsideInterface(serverAnswer);

                //两个接口都建立了起来，将connected标识符设置为true
                connected = true;

                //所有其他app发出的数据包都会进入这个输入流中，我们将其处理后，转发
                FileInputStream in = new FileInputStream(insideInterface.getFileDescriptor());
                //从服务器收到的数据，进行解包后，通过这个输出流返还给相应的app
                FileOutputStream out = new FileOutputStream(insideInterface.getFileDescriptor());

                //为数据包分配缓冲区
                ByteBuffer packet = ByteBuffer.allocate(MAX_PACKET_SIZE);



                //标识符，代表在一次循环中是否有数据被读到
                boolean haveData;
                //现在此线程中，一直执行这个循环，直到连接断开为止
                while (true) {

                    haveData = false;

                    //从对内的接口中读出其他APP发出去的数据
                    int length = in.read(packet.array());

                    if (length > 0) {

                        packet.limit(length);
                        //todo 加密函数
                        tunnel.write(packet);

//                        String rs = getSHA256StrJava("test");

                        packet.clear();


                        haveData = true;

                    }
                    //从对外的接口中读出服务器发回来的数据
                    length = tunnel.read(packet);
                    if (length > 0) {

//                        if (packet.get(0) != 0) {
                            //todo 解密函数
                            // Write the incoming packet to the output stream.
                            out.write(packet.array(), 0, length);
//                        }
                        packet.clear();

                        haveData = true;

                    }

                    //如果没有读到任何数据，就让线程睡一会儿
                    //这条语句不加也可以，但为了我电脑和手机的寿命，还是加一句吧
                    if (!haveData) {
                        Thread.sleep(IDLE_INTERVAL_MS);
                    }
                }
            }
            //若获取失败，返回false
            else {
                return false;
            }

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        return connected;

    }

    //与服务器进行连接，并将结果返回
    private boolean getOutsideInterface(DatagramChannel tunnel) throws IOException, InterruptedException {

        //TODO 将密钥以sha256加密，并等待服务器返回认证信息

        //目前先以明文传输密钥

        //分配缓冲区来进行握手
        ByteBuffer packet = ByteBuffer.allocate(1024);


        //写完数据后进行翻转，将一个处于存数据状态的缓冲区变为一个处于准备取数据的状态
        String strKey = mKey.toString();



        byte [] rs = getSHA256StrJava(strKey).getBytes();
        packet.put((byte) 0).put(mKey).flip();

        //TODO 取消了多次发包
        //将下次读写的位置置为0
        packet.position(0);
        tunnel.write(packet);

        packet.clear();

        //等待服务器相应
        for (int i = 0; i < MAX_HANDSHAKE_ATTEMPTS; ++i) {
            Thread.sleep(IDLE_INTERVAL_MS);



            int length = tunnel.read(packet);
            //查看收到的包第一个数字是不是0，若是则代表服务器响应连接
            if (length > 0 && packet.get(0) == 0) {
                //trim:去除trim两端的空白字符
                //将服务器的应答存入serverAnswer中
                serverAnswer = new String(packet.array(), 1, length - 1, US_ASCII).trim();
                return true;
            }
        }
        //若长时间未得到服务器响应，返回false
        return false;
    }

    //生成手机内部的数据接口，绝大部分app发出的ip包都会发送到这个接口中，
    //我们这个程序可以利用这个接口来获取用户的所有流量
    private ParcelFileDescriptor getInsideInterface(String answer) throws IllegalArgumentException {
        // Configure a builder while parsing the parameters.

        VpnService.Builder builder = mService.new Builder();

        //解析服务器传回的参数，并借此建立接口
        for (String parameter : answer.split(" ")) {
            String[] fields = parameter.split(",");
            try {
                switch (fields[0].charAt(0)) {
                    case 'm':
                        //MTU,虚拟网络端口的最大传输单元
                        builder.setMtu(Short.parseShort(fields[1]));
                        break;
                    case 'a':
                        //虚拟网络接口的ip地址
                        builder.addAddress(fields[1], Integer.parseInt(fields[2]));
                        break;
                    case 'r':
                        //路由范围，匹配上的ip包，才会传输到虚拟端口上。
                        //若是0.0.0.0/0，所有的ip包都会路由到虚拟端口上
                        builder.addRoute(fields[1], Integer.parseInt(fields[2]));
                        break;
                    case 'd':
                        //端口的DNS服务器地址
                        builder.addDnsServer(fields[1]);
                        break;
                    case 's':
                        //添加DNS域名的自动补齐
                        builder.addSearchDomain(fields[1]);
                        break;
                }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Bad parameter: " + parameter);
            }
        }

        //创建接口
        final ParcelFileDescriptor vpnInterface;

        vpnInterface = builder
                //VPN的名字，会在系统管理的与VPN连接相关的通知栏和对话框中显示出来
                .setSession(mIp)
                //建立
                .establish();

        //因为要对另一线程的变量进行设置，这里加锁
        synchronized (mService) {
            mOnEstablishListener.onEstablish(vpnInterface);
        }

        return vpnInterface;
    }



    //sha256相关
    public static String getSHA256StrJava(String str){
        MessageDigest messageDigest;
        String encodeStr = "";
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(str.getBytes("UTF-8"));
            encodeStr = byte2Hex(messageDigest.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return encodeStr;
    }

    private static String byte2Hex(byte[] bytes){
        StringBuffer stringBuffer = new StringBuffer();
        String temp = null;
        for (int i=0;i<bytes.length;i++){
            temp = Integer.toHexString(bytes[i] & 0xFF);
            if (temp.length()==1){
                //1得到一位的进行补0操作
                stringBuffer.append("0");
            }
            stringBuffer.append(temp);
        }
        return stringBuffer.toString();
    }

}
