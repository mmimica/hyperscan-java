package com.gliwka.hyperscan.wrapper;

import org.bytedeco.hyperscan.hs_database_t;
import org.bytedeco.hyperscan.hs_scratch_t;
import org.bytedeco.hyperscan.match_event_handler;
import org.bytedeco.javacpp.BytePointer;
import org.bytedeco.javacpp.Pointer;
import org.bytedeco.javacpp.SizeTPointer;

import java.io.Closeable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import static java.util.Collections.emptyList;
import static org.bytedeco.hyperscan.global.hyperscan.*;

/**
 * Scanner can be used with databases to scan for expressions in input string.
 */
public class Scanner implements Closeable {

    public Scanner() {
    }

    public Scanner(Database db) {
        this();
        allocScratch(db);
    }


    private static class NativeScratch extends hs_scratch_t {
        void registerDeallocator() {
            hs_scratch_t p = new hs_scratch_t(this);
            deallocator(() -> hs_free_scratch(p));
        }
    }

    private NativeScratch scratch = new NativeScratch();

    /**
     * Check if the hardware platform is supported
     *
     * @return true if supported, otherwise false
     */
    public static boolean getIsValidPlatform() {
        return hs_valid_platform() == 0;
    }


    /**
     * Get the version information for the underlying hyperscan library
     *
     * @return version string
     */
    public static String getVersion() {
        try (var p = hs_version()) {
            return p.getString();
        }
    }

    /**
     * Get the scratch space size in bytes
     *
     * @return count of bytes
     */
    public long getSize() {
        if (scratch == null) {
            throw new IllegalStateException("Scratch space has alredy been deallocated");
        }

        try (SizeTPointer size = new SizeTPointer(1)) {
            hs_scratch_size(scratch, size);
            return size.get();
        }
    }

    /**
     * Allocate a scratch space.  Must be called at least once with each database that will be used before scan is called.
     *
     * @param db Database containing expressions to use for matching
     */
    private void allocScratch(final Database db) {
        if (scratch == null) {
            throw new IllegalStateException("Scratch space has already been deallocated");
        }

        hs_database_t dbPointer = db.getDatabase();
        int hsError = hs_alloc_scratch(dbPointer, scratch);
        scratch.registerDeallocator();

        if (hsError != 0) {
            throw HyperscanException.hsErrorToException(hsError);
        }
    }

    /**
     * scan for a match in a string using a compiled expression database Can only be executed one at a time on a per instance basis
     *
     * @param db    Database containing expressions to use for matching
     * @param input String to match against
     * @return List of Matches
     */
    public List<Match> scan(final Database db, final String input) {
        if (scratch == null) {
            throw new IllegalStateException("Scratch space has already been deallocated");
        }

        var database = db.getDatabase();

        List<long[]> matchedIds = new ArrayList<>();

        try (var matchHandler = new match_event_handler() {
            public int call(int id, long from, long to, int flags, Pointer context) {
                long[] tuple = {id, from, to};
                matchedIds.add(tuple);
                return 0;
            }
        }) {

            var bytes = input.getBytes(StandardCharsets.UTF_8);
            try (var bytePointer = new BytePointer(ByteBuffer.wrap(bytes))) {
                int hsError = hs_scan(database, bytePointer, bytes.length, 0, scratch, matchHandler, null);

                if (hsError != 0) {
                    throw HyperscanException.hsErrorToException(hsError);
                }
            }

            if (matchedIds.isEmpty()) {
                return emptyList();
            }

            //if string length == byte length, all characters are 1 byte wide -> ASCII, no position mapping necessary
            if (bytes.length == input.length()) {
                return processMatches(matchedIds, input, bytes, db, position -> position);
            } else {
                final int[] byteToStringPosition = Utf8.byteToStringPositionMap(input, bytes.length);
                return processMatches(matchedIds, input, bytes, db, bytePosition -> byteToStringPosition[bytePosition]);
            }
        }
    }

    private List<Match> processMatches(List<long[]> matchedIds, String input, byte[] bytes, Database db, Function<Integer, Integer> position) {
        var matches = new ArrayList<Match>(matchedIds.size());

        matchedIds.forEach(tuple -> {
            int id = (int) tuple[0];
            long from = tuple[1];
            long to = tuple[2] < 1 ? 1 : tuple[2];
            String match = "";
            Expression matchingExpression = db.getExpression(id);

            int startIndex = position.apply((int) from);
            int endIndex = position.apply((int) to - 1);

            if (matchingExpression.getFlags().contains(ExpressionFlag.SOM_LEFTMOST)) {
                match = input.substring(startIndex, endIndex + 1);
            }

            if (bytes.length > 0) {
                matches.add(new Match(startIndex, endIndex, match, matchingExpression));
            } else {
                matches.add(new Match(0, 0, match, matchingExpression));
            }
        });

        return matches;
    }

    @Override
    public void close() {
        scratch.close();
        scratch = null;
    }
}
