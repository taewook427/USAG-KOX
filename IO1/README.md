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

#### Android Project

```python
mainfests/
    AndroidManifest.xml #set main activity, service, permissions
java/
    com.example.package/
        code.java #codes here
assets/ #app - new - folder - asset folder
    data.html #datas that can be used by app
res/
    drawable/ #drawable - new - vector asset - search, add
        icon.xml #icon or component xml
    layout/
        mainview.xml #screen xml
    mipmap/ #res - new - image asset - add foreground, background image
    values/
        themes.xml #general button, background design
        colors.xml
        strings.xml
        styles.xml #defines component design
    xml/
        config.xml #config for some apps
build.gradle.kts #file - project structure - dependency - add, version info
```

- Align and Sign Release build with jks keyfile
- There is two memory limit: Device limit and VM limit
    - Modern Android device RAM is 6~16 GB
    - But memory that one process can use is limited as VM memory, usually 256 MB
    - Use independent process to bypass this limit
- Declare largeheap in AndroidManifest to extend VM limit to 512 MB
- JNI Native Calls are not limited by VM memory
