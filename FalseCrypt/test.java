/*
 * structure:
 * lib/bclib.jar, lib/zstdlib.jar, Icons.java, Bencrypt.java, Opsec.java, Star.java, FalseCrypt.java, test.java
 * windows:
 * javac -cp ".;lib/*" Icons.java Bencrypt.java Opsec.java Star.java FalseCrypt.java test.java
 * java -cp ".;lib/*" test
 * mac/linux:
 * javac -cp ".:lib/*" Icons.java Bencrypt.java Opsec.java Star.java FalseCrypt.java test.java
 * java -cp ".:lib/*" test
 */
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class test {
    public static FalseCrypt.PEVFS buildPEVFS() throws Exception {
        // set CIDkey, WriteAuth
        byte[] ckey = new byte[32];
        byte[] wauth = new byte[32];
        System.arraycopy("abcdefghabcdefghabcdefghabcdefgh".getBytes(StandardCharsets.UTF_8), 0, ckey, 0, 32);
        System.arraycopy("abcdefghabcdefghabcdefghabcdefgh".getBytes(StandardCharsets.UTF_8), 0, wauth, 0, 32);

        // set VUser data
        FalseCrypt.VUser vu = new FalseCrypt.VUser();
        vu.StorageName = "test";
        vu.UserName = "root";
        vu.SecureLevel = FalseCrypt.SL_TOPSECRET;
        vu.UserBitA = "test";
        vu.UserBitB = "test";
        vu.CIDpad = new byte[] { 1, 2, 3, 4, 5, 6 };
        vu.CIDkey = ckey;
        vu.WriteAuth = wauth;

        // UID counter
        Map<Long, FalseCrypt.VMeta> vm = new HashMap<>();
        long[] counters = new long[] { 0, 1000000 }; // counters[0] = fCount, counters[1] = fileCount

        // generate tree
        FalseCrypt.VFile root = walk(1, vm, counters);
        FalseCrypt.PEVFS p = new FalseCrypt.PEVFS();
        p.Init(vu, root, vm, FalseCrypt.SL_TOPSECRET, (byte) 48);
        return p;
    }

    private static FalseCrypt.VFile walk(int depth, Map<Long, FalseCrypt.VMeta> vm, long[] counters) throws Exception {
        counters[0]++; // fCount++
        long uid = counters[0];

        // init folder node
        FalseCrypt.VFile f = new FalseCrypt.VFile();
        f.Children = new ArrayList<>();
        f.SetUID(uid);
        f.SetSL(FalseCrypt.SL_CONTROLLED);
        f.SetFlag(FalseCrypt.FLAG_DIR, true);

        // init folder metadata
        String name = "abcdefghabcdefghabcdefghabcdefgh";
        FalseCrypt.VMeta folderMeta = new FalseCrypt.VMeta();
        folderMeta.Name = name;
        folderMeta.EdTime = 12345678;
        vm.put(uid, folderMeta);

        // add 2 children until depth 17
        if (depth < 18) {
            f.Children.add(walk(depth + 1, vm, counters));
            f.Children.add(walk(depth + 1, vm, counters));
        } else {
            // add 10 files at the end
            Bencrypt.Masker mask = Bencrypt.Masker.GetMasker();
            byte[] rawKey = "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh".getBytes(StandardCharsets.UTF_8);
            byte[] maskedKey = mask.XOR(rawKey);

            for (int i = 0; i < 10; i++) {
                counters[1]++; // fileCount++
                long fuid = counters[1];

                // init file node
                FalseCrypt.VFile child = new FalseCrypt.VFile();
                child.Children = new ArrayList<>();
                child.SetUID(fuid);
                child.SetSL(FalseCrypt.SL_CONTROLLED);

                // init file metadata
                FalseCrypt.VMeta fileMeta = new FalseCrypt.VMeta();
                fileMeta.Name = "abcdefghabcdefghabcdefghabcdefgh";
                fileMeta.EdTime = 12345678;
                fileMeta.Size = 12345678;
                fileMeta.EncSize = 12345678;
                System.arraycopy(maskedKey, 0, fileMeta.Key, 0, 48);

                vm.put(fuid, fileMeta);
                f.Children.add(child);
            }
        }
        return f;
    }

    public static void countPEVFS(FalseCrypt.VFile node, int[] counts) {
        // counts[0] = folders, counts[1] = files
        if (node.GetFlag(FalseCrypt.FLAG_DIR)) {
            counts[0]++;
        } else {
            counts[1]++;
        }
        if (node.Children != null) {
            for (int i = 0; i < node.Children.size(); i++) {
                countPEVFS(node.Children.get(i), counts);
            }
        }
    }

    public static void main(String[] args) {
        try {
            // Helper Functions
            byte[] temp = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM".getBytes(StandardCharsets.UTF_8);
            byte[] res = FalseCrypt.Decompress(FalseCrypt.Compress(temp));
            System.out.printf("Zstd: %b\n", Arrays.equals(temp, res));

            // [166 175 112 183 175 63 66 53 45 120 62 139 7 81 94 67] [32 191 9 139 107 223 33 111 37 153 225 55 216 97 118 40]
            byte[] shaOut = FalseCrypt.SHA3256("0000".getBytes(StandardCharsets.UTF_8));
            byte[] hmacOut = FalseCrypt.HMAC3256("0000".getBytes(StandardCharsets.UTF_8), "00000000".getBytes(StandardCharsets.UTF_8));
            System.out.printf("SHA: %s %s\n", Arrays.toString(Arrays.copyOfRange(shaOut, 0, 16)), Arrays.toString(Arrays.copyOfRange(hmacOut, 0, 16)));

            // PEVFS Pack
            FalseCrypt.PEVFS pevfs = buildPEVFS();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            try {
                pevfs.Pack("hkey".getBytes(StandardCharsets.UTF_8), "salt".getBytes(StandardCharsets.UTF_8), "msg", buf);
                System.out.println("PEVFS Pack success");
            } catch (Exception e) {
                System.out.printf("PEVFS Pack %s\n", e.getMessage());
            }
            byte[] packedBytes = buf.toByteArray();
            System.out.printf("Packed Size %d\n", packedBytes.length);

            // Test PEVFS View
            FalseCrypt.PEVFS.ViewResult vr = pevfs.View(new ByteArrayInputStream(packedBytes));
            System.out.printf("PEVFS View %b %b\n", "msg".equals(vr.Msg), Arrays.equals(vr.Salt, "salt".getBytes(StandardCharsets.UTF_8)));

            // PEVFS Unpack
            try {
                pevfs.Unpack("hkey".getBytes(StandardCharsets.UTF_8), new ByteArrayInputStream(packedBytes));
                System.out.println("PEVFS Unpack success");
            } catch (Exception e) {
                System.out.printf("PEVFS Unpack %s\n", e.getMessage());
            }

            // Test PEVFS Account
            System.out.printf("VUser: %b %b %b %b %b %b %b %b\n",
                    "test".equals(pevfs.Account.StorageName),
                    "root".equals(pevfs.Account.UserName),
                    pevfs.Account.SecureLevel == FalseCrypt.SL_TOPSECRET,
                    "test".equals(pevfs.Account.UserBitA),
                    "test".equals(pevfs.Account.UserBitB),
                    Arrays.equals(pevfs.Account.CIDpad, new byte[] { 1, 2, 3, 4, 5, 6 }),
                    Arrays.equals(pevfs.Account.CIDkey, "abcdefghabcdefghabcdefghabcdefgh".getBytes(StandardCharsets.UTF_8)),
                    Arrays.equals(pevfs.Account.WriteAuth, "abcdefghabcdefghabcdefghabcdefgh".getBytes(StandardCharsets.UTF_8)));

            // Test PEVFS File count
            int[] counts = new int[2];
            countPEVFS(pevfs.Root, counts);
            System.out.printf("Count: %d %d\n", counts[0], counts[1]);

            // Test PEVFS Folder node
            FalseCrypt.VMeta fMeta = pevfs.Meta.get(1L);
            boolean fOk = (fMeta != null);
            System.out.printf("Folder Meta: %b %b %b\n", fOk, fOk && "abcdefghabcdefghabcdefghabcdefgh".equals(fMeta.Name), fOk && fMeta.EdTime == 12345678);

            // Test PEVFS File key
            byte[] expectedKey = "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh".getBytes(StandardCharsets.UTF_8);
            FalseCrypt.VMeta fileMeta = pevfs.Meta.get(1000001L);
            Bencrypt.Masker mask = Bencrypt.Masker.GetMasker();
            byte[] unmaskedKey = mask.XOR(fileMeta.Key);
            System.out.printf("File Meta: %b %b %b %b %b\n",
                    "abcdefghabcdefghabcdefghabcdefgh".equals(fileMeta.Name),
                    fileMeta.EdTime == 12345678,
                    fileMeta.Size == 12345678,
                    fileMeta.EncSize == 12345678,
                    Arrays.equals(unmaskedKey, expectedKey));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}