## SVCC1

서비스 통신 채널 Service communication channel

#### Java

```java
class SVCC1 {
    class VEvent {
        String action;
        Parcelable data;

        VEvent(String action, Parcelable data)
    }

    // int, long, double, string 4 each
    MutableLiveData<Integer>[] IntSlots
    MutableLiveData<Long>[] LongSlots
    MutableLiveData<Double>[] DoubleSlots
    MutableLiveData<String>[] StringSlots
    MutableLiveData<VEvent> ToSvcBus
    MutableLiveData<VEvent> ToMainBus

    synchronized SVCC1 getChan() // singleton generator

    void SetInt(int index, int value)
    void SetLong(int index, long value)
    void SetDouble(int index, double value)
    void SetString(int index, String value)
    void SendToSvc(String action, Parcelable data)
    void SendToMain(String action, Parcelable data)
}
```