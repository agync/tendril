# The JNI layer builds this exception by name, so R8 must not rename or remove it.
-keep class dev.tendril.TendrilRefusedException { *; }
