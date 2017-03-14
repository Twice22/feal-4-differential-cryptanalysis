package feal4;

import java.awt.Container;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.*;
import javax.xml.bind.DatatypeConverter;

public class FEAL extends JApplet
    implements ActionListener
{

    public FEAL()
    {
    }

    static byte rot2(byte byte0)
    {
        return (byte)((byte0 & 0xff) << 2 | (byte0 & 0xff) >>> 6);
    }

    static byte g0(byte byte0, byte byte1)
    {
        return rot2((byte)(byte0 + byte1 & 0xff));
    }

    static byte g1(byte byte0, byte byte1)
    {
        return rot2((byte)(byte0 + byte1 + 1 & 0xff));
    }

    static int pack(byte abyte0[], int i)
    {
        return (abyte0[i + 3] & 0xff) << 24 | (abyte0[i + 2] & 0xff) << 16 | (abyte0[i + 1] & 0xff) << 8 | abyte0[i] & 0xff;
    }

    static void unpack(int i, byte abyte0[], int j)
    {
        abyte0[j] = (byte)i;
        abyte0[j + 1] = (byte)(i >>> 8);
        abyte0[j + 2] = (byte)(i >>> 16);
        abyte0[j + 3] = (byte)(i >>> 24);
    }

    static int f(int i)
    {
        byte abyte0[] = new byte[4];
        byte abyte1[] = new byte[4];
        unpack(i, abyte0, 0);
        abyte1[1] = g1((byte)((abyte0[0] ^ abyte0[1]) & 0xff), (byte)((abyte0[2] ^ abyte0[3]) & 0xff));
        abyte1[0] = g0((byte)(abyte0[0] & 0xff), (byte)(abyte1[1] & 0xff));
        abyte1[2] = g0((byte)(abyte1[1] & 0xff), (byte)((abyte0[2] ^ abyte0[3]) & 0xff));
        abyte1[3] = g1((byte)(abyte1[2] & 0xff), (byte)(abyte0[3] & 0xff));
        return pack(abyte1, 0);
    }

    static void encrypt(byte abyte0[], int ai[])
    {
        int i = pack(abyte0, 0) ^ ai[4];
        int j = i ^ pack(abyte0, 4) ^ ai[5];
        for(int l = 0; l < rounds; l++)
        {
            int k = j;
            j = i ^ f(j ^ ai[l]);
            i = k;
        }

        i ^= j;
        unpack(j, abyte0, 0);
        unpack(i, abyte0, 4);
    }

    static void decrypt(byte abyte0[], int ai[])
    {
        int j = pack(abyte0, 0);
        int i = j ^ pack(abyte0, 4);
        for(int l = 0; l < rounds; l++)
        {
            int k = i;
            i = j ^ f(i ^ ai[rounds - 1 - l]);
            j = k;
        }

        j ^= i;
        i ^= ai[4];
        j ^= ai[5];
        unpack(i, abyte0, 0);
        unpack(j, abyte0, 4);
    }

    public void init()
    {
        Container container = getContentPane();
        container.setLayout(new GridLayout(2, 3));
        in = new JLabel("Input (16 hex digits)");
        out = new JLabel("Output (16 hex digits)");
        input = new JTextField(16);
        output = new JTextField(16);
        encrypt = new JButton("Encrypt-->");
        decrypt = new JButton("<--Decrypt");
        container.add(in);
        container.add(encrypt);
        container.add(out);
        container.add(input);
        container.add(decrypt);
        container.add(output);
        encrypt.addActionListener(this);
        decrypt.addActionListener(this);
    }

    public void actionPerformed(ActionEvent actionevent)
    {
        if(actionevent.getSource() == encrypt)
            try
            {
                String s = input.getText();
                if(s.length() != 16)
                    throw new Exception();
                byte abyte0[] = DatatypeConverter.parseHexBinary(s);
                encrypt(abyte0, key);
                output.setText(DatatypeConverter.printHexBinary(abyte0));
            }
            catch(Exception exception)
            {
                output.setText("Invalid input");
            }
        else
            try
            {
                String s1 = output.getText();
                if(s1.length() != 16)
                    throw new Exception();
                byte abyte1[] = DatatypeConverter.parseHexBinary(s1);
                decrypt(abyte1, key);
                input.setText(DatatypeConverter.printHexBinary(abyte1));
            }
            catch(Exception exception1)
            {
                input.setText("Invalid output");
            }
    }

    JTextField input;
    JTextField output;
    JButton encrypt;
    JButton decrypt;
    JLabel in;
    JLabel out;
    private int key[] = {
        0xc63f1a1a, 0xe768bb42, 0x948c886f, 0x924370ca, 0x62bffac2, 0x5581fc95
    };
    static int rounds = 4;

}
