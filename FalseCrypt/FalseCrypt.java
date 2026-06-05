// testXXXb : FalseCrypt
/*
* external library zstd-jni is required
* desktop: lib/zstdlib.jar
* android: gradle dependency com.github.luben:zstd-jni:1.5.7-9
*/
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.HashMap;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import com.github.luben.zstd.Zstd;
import com.github.luben.zstd.ZstdInputStream;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class FalseCrypt {
    private static volatile Object DUMMY;

    private static void sclear(byte[] data) {
        java.util.Arrays.fill(data, (byte) 0);
        DUMMY = data;
    }

    public static void ClearDummy() {
        DUMMY = null;
    }

    // Helper Functions
    public static byte[] Compress(byte[] data) {
        if (data == null)
            return null;
        return Zstd.compress(data);
    }

    public static byte[] Decompress(byte[] data) throws IOException {
        if (data == null)
            return null;
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
                ZstdInputStream zis = new ZstdInputStream(bais);
                ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int len;
            while ((len = zis.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
            }
            return baos.toByteArray();
        }
    }

    public static byte[] SHA3256(byte[] data) {
        if (data == null)
            return null;
        SHA3Digest digest = new SHA3Digest(256);
        byte[] result = new byte[digest.getDigestSize()];
        digest.update(data, 0, data.length);
        digest.doFinal(result, 0);
        return result;
    }

    public static byte[] HMAC3256(byte[] key, byte[] data) {
        if (key == null || data == null)
            return null;
        HMac hmac = new HMac(new SHA3Digest(256));
        hmac.init(new KeyParameter(key));
        hmac.update(data, 0, data.length);
        byte[] result = new byte[hmac.getMacSize()];
        hmac.doFinal(result, 0);
        return result;
    }

    // File Node Flags
    public static final byte FLAG_WORKING = 7;
    public static final byte FLAG_DIR = 6;
    public static final byte FLAG_EMPTY = 5;
    public static final byte FLAG_COMPRESS = 4;
    public static final byte FLAG_SECURE_A = 3;
    public static final byte FLAG_SECURE_B = 2;
    public static final byte FLAG_USER_A = 1;
    public static final byte FLAG_USER_B = 0;

    // Security Levels
    public static final byte SL_TOPSECRET = 3;
    public static final byte SL_SECRET = 2;
    public static final byte SL_CONFIDENTIAL = 1;
    public static final byte SL_CONTROLLED = 0;

    // Account Data
    public static class VUser {
        public String StorageName;
        public String UserName;
        public byte SecureLevel;
        public String UserBitA;
        public String UserBitB;

        public byte[] CIDpad; // 6B
        public byte[] CIDkey; // 32B, masked
        public byte[] WriteAuth; // 32B

        private Bencrypt.Masker mask;

        byte[] pack() throws IOException {
            Map<String, byte[]> mp = new HashMap<>();
            mp.put("sname", this.StorageName.getBytes(StandardCharsets.UTF_8));
            mp.put("uname", this.UserName.getBytes(StandardCharsets.UTF_8));
            mp.put("slvl", new byte[] { this.SecureLevel });
            mp.put("ubita", this.UserBitA.getBytes(StandardCharsets.UTF_8));
            mp.put("ubitb", this.UserBitB.getBytes(StandardCharsets.UTF_8));
            mp.put("cpad", this.CIDpad);

            byte[] ck = mask.XOR(this.CIDkey);
            try {
                mp.put("ckey", ck);
                mp.put("wauth", this.WriteAuth);
                return new Opsec().EncodeCfg(mp);
            } finally {
                sclear(ck);
            }
        }

        void unpack(byte[] data) throws Exception {
            Map<String, byte[]> mp = new Opsec().DecodeCfg(data);

            this.StorageName = new String(mp.get("sname"), StandardCharsets.UTF_8);
            this.UserName = new String(mp.get("uname"), StandardCharsets.UTF_8);
            this.SecureLevel = mp.get("slvl")[0];
            this.UserBitA = new String(mp.get("ubita"), StandardCharsets.UTF_8);
            this.UserBitB = new String(mp.get("ubitb"), StandardCharsets.UTF_8);

            this.CIDpad = mp.get("cpad").clone();
            this.CIDkey = mask.XOR(mp.get("ckey")); // XOR 마스킹 복원 및 반영
            this.WriteAuth = mp.get("wauth").clone();
        }

        public byte[] GetCID(long uid, int idx) throws Exception {
            byte[] key = mask.XOR(this.CIDkey);
            if (key == null)
                return null;
            byte[] temp = new byte[16];

            try {
                ByteBuffer buf = ByteBuffer.wrap(temp).order(ByteOrder.LITTLE_ENDIAN);

                // 6B UID (Little Endian)
                ByteBuffer uidBuf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(uid);
                buf.put(uidBuf.array(), 0, 6);

                // 4B Index (Little Endian)
                buf.putInt(idx);

                // 6B Padding
                buf.put(this.CIDpad, 0, 6);

                // AES ECB NoPadding
                SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
                Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                return cipher.doFinal(temp);
            } finally {
                sclear(key);
            }
        }
    }

    public static class VFile {
        public final byte[] Data = new byte[8];
        public List<VFile> Children = new ArrayList<>();

        public boolean GetFlag(byte tp) {
            return ((Data[1] & 0xFF) >> tp & 1) == 1;
        }

        public void SetFlag(byte tp, boolean val) {
            if (val) {
                Data[1] |= (byte) (1 << tp);
            } else {
                Data[1] &= (byte) ~(1 << tp);
            }
        }

        public byte GetSL() {
            if (GetFlag(FLAG_SECURE_A)) {
                if (GetFlag(FLAG_SECURE_B)) {
                    return SL_TOPSECRET;
                } else {
                    return SL_SECRET;
                }
            } else {
                if (GetFlag(FLAG_SECURE_B)) {
                    return SL_CONFIDENTIAL;
                } else {
                    return SL_CONTROLLED;
                }
            }
        }

        public void SetSL(byte sl) {
            switch (sl) {
                case SL_TOPSECRET:
                    SetFlag(FLAG_SECURE_A, true);
                    SetFlag(FLAG_SECURE_B, true);
                    break;
                case SL_SECRET:
                    SetFlag(FLAG_SECURE_A, true);
                    SetFlag(FLAG_SECURE_B, false);
                    break;
                case SL_CONFIDENTIAL:
                    SetFlag(FLAG_SECURE_A, false);
                    SetFlag(FLAG_SECURE_B, true);
                    break;
                case SL_CONTROLLED:
                    SetFlag(FLAG_SECURE_A, false);
                    SetFlag(FLAG_SECURE_B, false);
                    break;
            }
        }

        public long GetUID() {
            long uid = 0;
            for (int i = 7; i >= 2; i--) {
                uid <<= 8;
                uid |= (Data[i] & 0xFF);
            }
            return uid;
        }

        public void SetUID(long uid) {
            long temp = uid;
            for (int i = 2; i <= 7; i++) {
                Data[i] = (byte) temp;
                temp >>= 8;
            }
        }
    }

    public static class VMeta {
        public String Name;
        public long EdTime;

        public final byte[] Key = new byte[48]; // masked
        public long Size;
        public long EncSize;
    }

    public static class PEVFS {
        public VUser Account;
        public VFile Root;
        public Map<Long, VMeta> Meta;

        public byte SecureLvl;
        public byte Keylen;
        public Bencrypt.Masker Mask;

        public static class ViewResult {
            public String Msg;
            public byte[] Salt;

            public ViewResult(String msg, byte[] msgInfo) {
                this.Msg = msg;
                this.Salt = msgInfo;
            }
        }

        public void Init(VUser vu, VFile vf, Map<Long, VMeta> vm, byte sl, byte kl) {
            this.Account = vu;
            this.Root = vf;
            this.Meta = (vm == null) ? new HashMap<>() : vm;
            this.SecureLvl = sl;
            this.Keylen = kl;
            this.Mask = Bencrypt.Masker.GetMasker(-1);
            this.Account.mask = this.Mask;
        }

        public ViewResult View(InputStream src) throws Exception {
            Opsec ops = new Opsec();
            ops.Reset();
            byte[] header = ops.Read(src, 0);
            if (header == null || header.length == 0) {
                throw new IOException("Unexpected end of opsec header stream");
            }
            ops.View(header);
            return new ViewResult(ops.Msg, ops.MsgInfo);
        }

        public void Pack(byte[] hkey, byte[] salt, String msg, OutputStream dst) throws Exception {
            // set TarWriter and error handler
            Star.TarWriter tw = new Star.TarWriter();
            tw.Open(null);
            final Throwable[] asyncErrors = new Throwable[3];

            // pack structure data
            Thread structThread = new Thread(() -> {
                try (ByteArrayOutputStream sBuf = new ByteArrayOutputStream()) {
                    packStruct(sBuf, Root, (byte) 0);
                    byte[] sDat = sBuf.toByteArray();
                    synchronized (tw) {
                        tw.Write("struct", sDat, 0644);
                    }
                    sclear(sDat);
                } catch (Throwable t) {
                    asyncErrors[0] = t;
                }
            });

            // pack metadata
            Thread metaThread = new Thread(() -> {
                try (ByteArrayOutputStream mBuf = new ByteArrayOutputStream()) {
                    packMeta(mBuf, Root);
                    byte[] mDat = mBuf.toByteArray();
                    synchronized (tw) {
                        tw.Write("meta", mDat, 0644);
                    }
                    sclear(mDat);
                } catch (Throwable t) {
                    asyncErrors[1] = t;
                }
            });

            // pack account data
            Thread userThread = new Thread(() -> {
                try {
                    byte[] uDat = Account.pack();
                    synchronized (tw) {
                        tw.Write("user", uDat, 0644);
                    }
                    sclear(uDat);
                } catch (Throwable t) {
                    asyncErrors[2] = t;
                }
            });

            // start threads, handle errors
            structThread.start();
            metaThread.start();
            userThread.start();

            structThread.join();
            metaThread.join();
            userThread.join();

            for (Throwable err : asyncErrors) {
                if (err != null) {
                    byte[] garbage = tw.Close();
                    tw.close();
                    sclear(garbage);
                    throw new Exception("PEVFS packing internal " + err.toString(), err);
                }
            }

            // get packed tar
            byte[] tarData = tw.Close();
            tw.close();
            if (tarData == null)
                throw new IOException("Failed to close and retrieve tar payload");

            // write complete data to dst
            try {
                Opsec ops = new Opsec();
                ops.Reset();
                ops.Msg = msg;
                ops.MsgInfo = salt;

                Bencrypt.SymMaster sm = new Bencrypt.SymMaster("gcmx1", new byte[44]);
                ops.BodySize = sm.AfterSize(tarData.length);
                ops.BodyAlgo = "gcmx1";
                ops.BodyInfo = "tar1".getBytes(StandardCharsets.UTF_8);

                byte[] header = ops.Encpw("sha3", hkey, null);

                long writed = 0;
                byte[] ico = Icons.ZipWebp;
                byte[] prehead = new byte[ico.length + (128 - ico.length % 128)];
                System.arraycopy(ico, 0, prehead, 0, ico.length);

                writed += prehead.length;
                dst.write(prehead);

                writed += header.length + 6;
                if (header.length >= 65535) {
                    writed += 2;
                }
                ops.Write(dst, header);

                sm = new Bencrypt.SymMaster("gcmx1", ops.BodyKey);
                try (java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(tarData)) {
                    sm.EnFile(bais, tarData.length, dst);
                }
                writed += ops.BodySize;

                long padLen = Opsec.PadLen(writed);
                if (padLen > 0) {
                    Opsec.PadFile(dst, padLen);
                }
            } finally {
                sclear(tarData);
                tarData = null;
            }
        }

        public void Unpack(byte[] hkey, InputStream src) throws Exception {
            // read ad opsec format
            Opsec ops = new Opsec();
            ops.Reset();

            byte[] header = ops.Read(src, 0);
            ops.View(header);
            ops.Decpw(hkey, null);

            Bencrypt.SymMaster sm = new Bencrypt.SymMaster(ops.BodyAlgo, ops.BodyKey);
            byte[] tarData;
            try (ByteArrayOutputStream tBuf = new ByteArrayOutputStream()) {
                sm.DeFile(src, ops.BodySize, tBuf);
                tarData = tBuf.toByteArray();
            }

            // set data components
            final byte[][] components = new byte[3][];
            try (Star.TarReader tr = new Star.TarReader()) {
                tr.Open(new java.io.ByteArrayInputStream(tarData));
                while (tr.Next()) {
                    if (!tr.IsDir) {
                        switch (tr.Name) {
                            case "struct":
                                components[0] = tr.Read();
                                break;
                            case "meta":
                                components[1] = tr.Read();
                                break;
                            case "user":
                                components[2] = tr.Read();
                                break;
                        }
                    }
                }
            } finally {
                sclear(tarData);
                tarData = null;
            }

            final Throwable[] asyncErrors = new Throwable[3];

            // unpack structure data
            Thread structThread = new Thread(() -> {
                try {
                    if (components[0] != null) {
                        int[] stRef = new int[] { 0 };
                        PEVFS.this.Root = unpackStruct(components[0], stRef, components[0].length, (byte) 0);
                    }
                } catch (Throwable t) {
                    asyncErrors[0] = t;
                } finally {
                    sclear(components[0]);
                    components[0] = null;
                }
            });

            // unpack metadata
            Thread metaThread = new Thread(() -> {
                try {
                    if (components[1] != null) {
                        PEVFS.this.Meta = new HashMap<>();
                        unpackMeta(components[1]);
                    }
                } catch (Throwable t) {
                    asyncErrors[1] = t;
                } finally {
                    sclear(components[1]);
                    components[1] = null;
                }
            });

            // unpack account data
            Thread userThread = new Thread(() -> {
                try {
                    if (components[2] != null) {
                        PEVFS.this.Account.unpack(components[2]);
                    }
                } catch (Throwable t) {
                    asyncErrors[2] = t;
                } finally {
                    sclear(components[2]);
                    components[2] = null;
                }
            });

            // start thread, handle errors
            structThread.start();
            metaThread.start();
            userThread.start();

            structThread.join();
            metaThread.join();
            userThread.join();

            for (Throwable err : asyncErrors) {
                if (err != null)
                    throw new Exception("PEVFS Unpacking internal " + err.toString(), err);
            }
        }

        void packStruct(ByteArrayOutputStream buf, VFile node, byte depth) throws Exception {
            // check secure level
            if (node.GetSL() > this.SecureLvl)
                return;
            node.Data[0] = depth;
            buf.write(node.Data); // 1B depth, 1B flags, 6B UID
            node.Data[0] = 0;

            // repeat for children
            if ((depth & 0xFF) == 255 && !node.Children.isEmpty()) {
                throw new Exception("File tree exceeds maximum depth");
            }
            for (int i = 0; i < node.Children.size(); i++) {
                packStruct(buf, node.Children.get(i), (byte) ((depth & 0xFF) + 1));
            }
        }

        void packMeta(ByteArrayOutputStream buf, VFile node) throws Exception {
            // check secure level, get data
            if (node.GetSL() > this.SecureLvl)
                return;
            VMeta meta = this.Meta.get(node.GetUID());
            if (meta == null) {
                throw new Exception("Cannot find file node metadata");
            }

            buf.write(node.Data, 2, 6); // 6B UID
            if (meta.Name.indexOf('\0') >= 0) {
                throw new Exception("Null byte in file name");
            }
            buf.write(meta.Name.getBytes(StandardCharsets.UTF_8));
            buf.write(0); // C-style name string

            byte[] temp = new byte[8];
            ByteBuffer.wrap(temp).order(ByteOrder.LITTLE_ENDIAN).putLong(meta.EdTime);
            buf.write(temp); // 8B EdTime

            if (node.GetFlag(FLAG_DIR) || node.GetFlag(FLAG_EMPTY)) {
                buf.write(0); // pass dir or empty
            } else {
                buf.write(this.Keylen); // 1B keylen
                byte[] targetKey = new byte[this.Keylen & 0xFF];
                System.arraycopy(meta.Key, 0, targetKey, 0, targetKey.length);

                byte[] unmaskedKey = this.Mask.XOR(targetKey);
                buf.write(unmaskedKey); // write unmasked key
                sclear(unmaskedKey);

                ByteBuffer.wrap(temp).order(ByteOrder.LITTLE_ENDIAN).putLong(meta.Size);
                buf.write(temp); // 8B Size
                ByteBuffer.wrap(temp).order(ByteOrder.LITTLE_ENDIAN).putLong(meta.EncSize);
                buf.write(temp); // 8B EncSize
            }

            // repeat for children
            for (int i = 0; i < node.Children.size(); i++) {
                packMeta(buf, node.Children.get(i));
            }
        }

        VFile unpackStruct(byte[] full, int[] stRef, int ed, byte curdepth) throws Exception {
            // check position
            int st = stRef[0];
            if (st + 8 > ed) {
                throw new Exception("Unexpected end of structure data");
            }
            if (full[st] != curdepth) {
                throw new Exception("Invalid structure depth sequence");
            }

            // recover 8B
            VFile node = new VFile();
            System.arraycopy(full, st, node.Data, 0, 8);
            node.Data[0] = 0;
            st += 8;
            stRef[0] = st;

            // DFS parsing
            while (stRef[0] < ed && full[stRef[0]] == (byte) ((curdepth & 0xFF) + 1)) {
                VFile child = unpackStruct(full, stRef, ed, (byte) ((curdepth & 0xFF) + 1));
                node.Children.add(child);
            }
            return node;
        }

        void unpackMeta(byte[] data) throws Exception {
            ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

            while (buf.hasRemaining()) {
                // set UID
                VMeta meta = new VMeta();
                byte[] uidBuf = new byte[8];
                buf.get(uidBuf, 0, 6);
                long uid = ByteBuffer.wrap(uidBuf).order(ByteOrder.LITTLE_ENDIAN).getLong();

                // get name string, edtime
                ByteArrayOutputStream nameStream = new ByteArrayOutputStream();
                while (true) {
                    byte b = buf.get();
                    if (b == 0)
                        break;
                    nameStream.write(b);
                }
                meta.Name = nameStream.toString(StandardCharsets.UTF_8.name());
                meta.EdTime = buf.getLong();

                int keyLen = buf.get() & 0xFF; // get keylen
                if (keyLen > 0) { // write masked key
                    byte[] unmaskedKey = new byte[keyLen];
                    buf.get(unmaskedKey);

                    byte[] maskedKey = this.Mask.XOR(unmaskedKey);
                    sclear(unmaskedKey);
                    System.arraycopy(maskedKey, 0, meta.Key, 0, maskedKey.length);

                    // write size, encsize
                    meta.Size = buf.getLong();
                    meta.EncSize = buf.getLong();
                }
                this.Meta.put(uid, meta);
            }
        }
    }

    public static abstract class VirtualIO {
        public abstract void GetAccount(String username, OutputStream dst) throws IOException;

        public abstract void SetAccount(String username, InputStream src, long size) throws IOException;

        public abstract byte[] ReadChunk(byte[] cid) throws IOException;

        public abstract void WriteChunk(byte[] cid, byte[] data) throws IOException;

        public abstract void DelChunk(byte[] cid) throws IOException;
    }
}
