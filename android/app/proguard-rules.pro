# kotlinx.serialization keeps its generated serializers via annotations.
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class com.satyashield.app.data.** {
    *** Companion;
}
-keepclasseswithmembers class com.satyashield.app.data.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# NotificationListenerService is instantiated by the framework by name.
-keep class com.satyashield.app.service.SatyaNotificationListener { *; }
