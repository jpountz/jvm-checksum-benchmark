package net.jpountz.jvm;

import java.util.Random;
import java.util.zip.Adler32;
import java.util.zip.CRC32;

import net.jpountz.xxhash.XXHash32;
import net.jpountz.xxhash.XXHashFactory;

import com.google.caliper.Benchmark;
import com.google.caliper.Param;
import com.google.caliper.runner.CaliperMain;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;

public class ChecksumBenchmark extends Benchmark {

  private static final CRC32 crc32 = new CRC32();
  private static final Adler32 adler32 = new Adler32();
  private static final HashFunction murmur3 = Hashing.murmur3_32();
  private static final HashFunction sha1 = Hashing.sha1();
  private static final HashFunction sha256 = Hashing.sha256();
  private static final HashFunction sha512 = Hashing.sha512();
  private static final HashFunction md5 = Hashing.md5();
  private static final HashFunction goodFastHash32 = Hashing.goodFastHash(32);
  private static final HashFunction goodFastHash64 = Hashing.goodFastHash(64);
  private static final XXHash32 xxhashJNI = XXHashFactory.nativeInstance().hash32();
  private static final XXHash32 xxhashUnsafe = XXHashFactory.unsafeInstance().hash32();
  private static final XXHash32 xxhashSafe = XXHashFactory.safeInstance().hash32();

  enum Checksum {
    JAVA_ARRAYS_HASHCODE {
      @Override
      long checksum(byte[] bytes, int size) {
        int hash = 1;
        for (int i = 0; i < size; ++i) {
          hash = 31 * hash + bytes[i];
        }
        return hash;
      }
    },
    CRC32 {
      long checksum(byte[] bytes, int size) {
        crc32.reset();
        crc32.update(bytes, 0, size);
        return crc32.getValue();
      }
    },
    ADLER32 {
      long checksum(byte[] bytes, int size) {
        adler32.reset();
        adler32.update(bytes, 0, size);
        return adler32.getValue();
      }
    },
    MURMUR2 {
      @Override
      long checksum(byte[] bytes, int size) {
        return MurmurHash2.hash32(bytes, 0, size);
      }
    },
    MURMUR3 {
      @Override
      long checksum(byte[] bytes, int size) {
        return murmur3.hashBytes(bytes, 0, size).asInt();
      }
    },
    SHA1 {
      @Override
      long checksum(byte[] bytes, int size) {
        return sha1.hashBytes(bytes, 0, size).asLong();
      }
    },
    SHA256 {
      @Override
      long checksum(byte[] bytes, int size) {
        return sha256.hashBytes(bytes, 0, size).asLong();
      }
    },
    SHA512 {
      @Override
      long checksum(byte[] bytes, int size) {
        return sha512.hashBytes(bytes, 0, size).asLong();
      }
    },
    MD5 {
      @Override
      long checksum(byte[] bytes, int size) {
        return md5.hashBytes(bytes, 0, size).asLong();
      }
    },
    GOOD_FAST_HASH_32 {
      @Override
      long checksum(byte[] bytes, int size) {
        return goodFastHash32.hashBytes(bytes, 0, size).asInt();
      }
    },
    GOOD_FAST_HASH_64 {
      @Override
      long checksum(byte[] bytes, int size) {
        return goodFastHash64.hashBytes(bytes, 0, size).asLong();
      }
    },
    XXH32_JNI {
      long checksum(byte[] bytes, int size) {
        return xxhashJNI.hash(bytes, 0, size, 0x9747b28c);
      }
    },
    XXH32_UNSAFE {
      long checksum(byte[] bytes, int size) {
        return xxhashUnsafe.hash(bytes, 0, size, 0x9747b28c);
      }
    },
    XXH32_SAFE {
      long checksum(byte[] bytes, int size) {
        return xxhashSafe.hash(bytes, 0, size, 0x9747b28c);
      }
    };
    
    abstract long checksum(byte[] bytes, int size);
  }

  @Param
  Checksum checksum;
  
  @Param({"16", "128", "1024", "8196", "65536", "524288"})
  int size;

  byte[] bytes;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    Random random = new Random();
    bytes = new byte[size];
    random.nextBytes(bytes);
  }
  
  public long timeChecksum(int reps) {
    long dummy = 0;
    for (int i = 0; i < reps; ++i) {
      dummy += checksum.checksum(bytes, size);
    }
    return dummy;
  }

  public static void main(String[] args) {
    CaliperMain.main(ChecksumBenchmark.class, args);
  }
  
}
