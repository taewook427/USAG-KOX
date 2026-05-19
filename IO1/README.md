## IO1

통합 입출력 인터페이스 Integrated input/output interface

#### Java

```java
class IO1 {
    class VFile implements Parcelable {
        VFile(File file)
        VFile(Uri uri, boolean isDir)

        boolean Rename(Context context, String newName)
        boolean Delete(Context context)
        Uri GetUri()

        boolean Exists(Context context)
        boolean IsDir(Context context)
        String GetName(Context context)
        long GetSize(Context context)
        List<VFile> ListDir(Context context)

        InputStream OpenReader(Context context)
        OutputStream OpenWriter(Context context, boolean isAppend)
        VFile CreateFile(Context context, String mimeType, String displayName)
        VFile CreateDir(Context context, String displayName)
    }

    void SelectFile(ActivityResultLauncher<Intent> launcher, boolean multi)
    void SelectFolder(ActivityResultLauncher<Intent> launcher)
    List<VFile> HandleSelectedFile(Intent data)
    VFile HandleSelectedFolder(Intent data)

    VFile GetLocal(Context context, String name)
    VFile CreateDownloadsFile(Context context, String name)
}
```