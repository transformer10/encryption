package ui;

import encryption.AES;
import encryption.DES;
import encryption.SymmetricalEncryption;
import encryption.Mode;
import util.Util;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.nio.charset.StandardCharsets;

import static java.awt.BorderLayout.CENTER;
import static java.awt.BorderLayout.SOUTH;

public class Window extends JFrame {
    private final JLabel inputChL, cipherL, plainTextL, keyL, runtimeL;
    private final JButton lockButton, unlockButton, clearButton, fileEncryButton, fileDecryButton;
    private final JTextArea inputChArea, cipherTextArea, plainTextArea;
    private final JTextField keyF;
    private final JPanel leftP, southP, downP;
    private Font kaishu;
    private SymmetricalEncryption c;

    {
        downP = new JPanel();
        kaishu = new Font(Font.DIALOG_INPUT, Font.BOLD, 12);
        keyL = new JLabel("Key");
        inputChL = new JLabel("Input text");
        cipherL = new JLabel("Cipher text");
        plainTextL = new JLabel("Plain text");
        runtimeL = new JLabel("Consuming time: ");

        lockButton = new JButton("Encryption🔐");

        unlockButton = new JButton("Decryption🔓");
        clearButton = new JButton("Clear");
        fileEncryButton = new JButton("File Encryption");
        fileDecryButton = new JButton("File Decryption");
        lockButton.setFont(kaishu);
        lockButton.setSize(new Dimension(1, 1));
        inputChArea = new JTextArea(5, 56);
        cipherTextArea = new JTextArea(5, 56);
        plainTextArea = new JTextArea(5, 56);
        keyF = new JTextField("", 56);
//        lockButton.setBorder(new Border() {
//            @Override
//            public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
//                g.drawRoundRect(0, 0, c.getWidth(), c.getHeight(), 30, 30);
//            }
//
//            @Override
//            public Insets getBorderInsets(Component c) {
//                return new Insets(0, 0, 0, 0);
//            }
//
//            @Override
//            public boolean isBorderOpaque() {
//                return false;
//            }
//        });
//        lockButton.setOpaque(false);

        leftP = new JPanel();
        southP = new JPanel();

        setVisible(true);
        setBounds(500, 300, 700, 480);
        setDefaultCloseOperation(EXIT_ON_CLOSE);

    }

    private void initLayout() {
        leftP.add(inputChL);
        leftP.add(inputChArea);
        leftP.add(keyL);
        leftP.add(keyF);
        leftP.add(cipherL);
        leftP.add(cipherTextArea);
        leftP.add(plainTextL);
        leftP.add(plainTextArea);
        leftP.add(runtimeL);

        southP.setLayout(new GridLayout(1, 5, 1, 50));
        southP.add(lockButton);
        southP.add(unlockButton);
        southP.add(clearButton);
        southP.add(fileEncryButton);
        southP.add(fileDecryButton);
        leftP.add(southP);
        add(leftP, CENTER);
        add(downP, SOUTH);
    }

    private void myAddActionListener() {
        lockButton.addActionListener(e -> {
            String origin = inputChArea.getText();
            String key = keyF.getText();
            c.setKey(key.getBytes(StandardCharsets.UTF_8));
            byte[] b = c.encryption(origin.getBytes(StandardCharsets.UTF_8));
            runtimeL.setText("Consuming time: " + Util.TIME + "ns");
            cipherTextArea.setText(Util.bytesToHex(b));
        });
        unlockButton.addActionListener(e -> {
            String origin = inputChArea.getText();
            String key = keyF.getText();
            c.setKey(key.getBytes(StandardCharsets.UTF_8));
            byte[] b = c.decryption(Util.hexToByteArray(origin));
            runtimeL.setText("Consuming time: " + Util.TIME + "ns");
            plainTextArea.setText(new String(b));
        });

        clearButton.addActionListener(e -> {
            inputChArea.setText(null);
            cipherTextArea.setText(null);
            plainTextArea.setText(null);
        });

        fileEncryButton.addActionListener(e -> {
            String f = showFileOpenDialog(this);
            if (f != null) {
                Util.fileEncry(f, keyF.getText(), c);
                runtimeL.setText("Consuming time: " + Util.TIME + "ns");
            }
        });
        fileDecryButton.addActionListener(e -> {
            String f = showFileOpenDialog(this);
            if (f != null) {
                Util.fileDecry(f, keyF.getText(), c);
                runtimeL.setText("Consuming time: " + Util.TIME + "ns");
            }
        });

    }

    private String showFileOpenDialog(Component parent) {
        // 创建一个默认的文件选取器
        JFileChooser fileChooser = new JFileChooser();

        // 设置默认显示的文件夹为当前文件夹
        fileChooser.setCurrentDirectory(new File("."));

        // 设置文件选择的模式（只选文件、只选文件夹、文件和文件均可选）
        fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        // 设置是否允许多选
        fileChooser.setMultiSelectionEnabled(true);

        // 添加可用的文件过滤器（FileNameExtensionFilter 的第一个参数是描述, 后面是需要过滤的文件扩展名 可变参数）
        //fileChooser.addChoosableFileFilter(new FileNameExtensionFilter("zip(*.zip, *.rar)", "zip", "rar"));
        // 设置默认使用的文件过滤器
        //fileChooser.setFileFilter(new FileNameExtensionFilter("image(*.jpg, *.png, *.gif)", "jpg", "png", "gif"));

        // 打开文件选择框（线程将被阻塞, 直到选择框被关闭）
        int result = fileChooser.showOpenDialog(parent);

        if (result == JFileChooser.APPROVE_OPTION) {
            // 如果点击了"确定", 则获取选择的文件路径
            File file = fileChooser.getSelectedFile();

            // 如果允许选择多个文件, 则通过下面方法获取选择的所有文件
            // File[] files = fileChooser.getSelectedFiles();
            return file.getAbsolutePath();
        }
        return null;
    }


    public Window(Mode mode) {
        super();
        if (mode == Mode.AES) {
            c = new AES();
            setTitle("encryption.AES Encryption/Decryption🔐");
        } else {
            c = new DES();
            setTitle("encryption.DES Encryption/Decryption🔐");
        }
        initLayout();
        myAddActionListener();
    }

}