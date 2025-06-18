/*
 * SimpleDns - Minimal DNS TXT record resolver.
 *
 * DNS Packet Header Structure (RFC 1035):
 * 
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |          ID           |           Flags           |        QDCOUNT         |
 * +-----------------------+---------------------------+-----------------------+
 * |        ANCOUNT        |        NSCOUNT            |        ARCOUNT         |
 * +-----------------------+---------------------------+-----------------------+
 * 
 * Field     Size (bytes)   Description
 * -----     ------------   -----------
 * ID             2         Identifier
 * Flags          2         Flags
 * QDCOUNT        2         Number of questions
 * ANCOUNT        2         Number of answers
 * NSCOUNT        2         Number of authority records
 * ARCOUNT        2         Number of additional records
 *
 * After the header, the question and answer sections follow.
 *
 * Question Section:
 * +---------------------+
 * |        QNAME        |  (domain name, as sequence of labels)
 * +---------------------+
 * |   QTYPE   | QCLASS  |  (2 bytes each)
 * +---------------------+
 *
 * Answer Section:
 * +---------------------+
 * |        NAME         |  (domain name, possibly as pointer)
 * +---------------------+
 * |   TYPE    |  CLASS  |  (2 bytes each)
 * +---------------------+
 * |           TTL           |  (4 bytes)
 * +---------------------+
 * |        RDLENGTH         |  (2 bytes)
 * +---------------------+
 * |        RDATA            |  (variable, RDLENGTH bytes)
 * +---------------------+
 */

package com.wireguard.util;

import android.net.DnsResolver;
import android.os.CancellationSignal;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class SimpleDns {

    private static final int CLASS_IN = 1;
    private static final int TYPE_TXT = 16;
    private static final int DNS_HEADER_LENGTH = 12;
    private static final int QTYPE_QCLASS_LENGTH = 4;
    private static final int ANSWER_FIXED_PART_LENGTH = 10;
    private static final int NSCOUNT_ARCOUNT_LENGTH = 4;
    private static final int POINTER_MASK = 0xC0;
    private static final int POINTER_FLAG = 0xC0;
    private static final int LABEL_TERMINATOR = 0;
    private static final int BYTE_MASK = 0xFF;
    private static final int SHORT_MASK = 0xFFFF;

    private static final Executor executor = Executors.newSingleThreadExecutor();

    public static CompletableFuture<List<String>> lookupTxt(String domain) {
        CompletableFuture<List<String>> future = new CompletableFuture<>();
        DnsResolver.getInstance().rawQuery(
                null,
                domain,
                CLASS_IN,
                TYPE_TXT,
                DnsResolver.FLAG_EMPTY,
                executor,
                new CancellationSignal(),
                new DnsResolver.Callback<byte[]>() {
                    @Override
                    public void onAnswer(byte[] raw, int rcode) {
                        try {
                            List<String> txts = parseTxt(raw);
                            future.complete(txts);
                        } catch (Exception e) {
                            future.completeExceptionally(e);
                        }
                    }

                    @Override
                    public void onError(DnsResolver.DnsException error) {
                        future.completeExceptionally(error);
                    }
                }
        );
        return future;
    }

    private static List<String> parseTxt(byte[] raw) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(raw);

        if (buffer.remaining() < DNS_HEADER_LENGTH) {
            throw new Exception("Invalid DNS response: too short");
        }
        buffer.position(4); // skip ID + flags
        int qdCount = buffer.getShort() & SHORT_MASK;
        int anCount = buffer.getShort() & SHORT_MASK;
        buffer.position(buffer.position() + NSCOUNT_ARCOUNT_LENGTH); // skip NSCOUNT + ARCOUNT

        // skip questions
        for (int i = 0; i < qdCount; i++) {
            skipName(buffer);
            if (buffer.remaining() < QTYPE_QCLASS_LENGTH) 
                throw new Exception("Invalid DNS question");
            buffer.position(buffer.position() + QTYPE_QCLASS_LENGTH); // skip QTYPE + QCLASS
        }

        List<String> results = new ArrayList<>();

        // parse answers
        for (int i = 0; i < anCount; i++) {
            skipName(buffer);

            if (buffer.remaining() < ANSWER_FIXED_PART_LENGTH) 
                throw new Exception("Invalid DNS answer");

            int type = buffer.getShort() & SHORT_MASK;
            int clazz = buffer.getShort() & SHORT_MASK;
            int ttl = buffer.getInt();
            int rdlength = buffer.getShort() & SHORT_MASK;

            if (buffer.remaining() < rdlength)
                throw new Exception("Invalid RDLENGTH");

            if (type == TYPE_TXT && clazz == CLASS_IN) {
                int end = buffer.position() + rdlength;
                while (buffer.position() < end) {
                    int txtLen = buffer.get() & BYTE_MASK;

                    if (buffer.remaining() < txtLen) 
                        throw new Exception("Invalid TXT length");

                    byte[] txtBytes = new byte[txtLen];
                    buffer.get(txtBytes);
                    results.add(new String(txtBytes, StandardCharsets.UTF_8));
                }
            } else {
                // skip unsupported record types
                buffer.position(buffer.position() + rdlength);
            }
        }
        return results;
    }

    private static void skipName(ByteBuffer buffer) throws Exception {
        while (true) {
            if (buffer.remaining() < 1)
                throw new Exception("Invalid DNS name");

            int len = buffer.get() & BYTE_MASK;
            if (len == LABEL_TERMINATOR) 
                return;  // end of name
            if ((len & POINTER_MASK) == POINTER_FLAG) {
                // pointer (2 bytes total)
                if (buffer.remaining() < 1)
                    throw new Exception("Invalid DNS pointer");

                buffer.get();
                return;
            }
            if (buffer.remaining() < len) 
                throw new Exception("Invalid DNS label");
                
            buffer.position(buffer.position() + len);
        }
    }
}
