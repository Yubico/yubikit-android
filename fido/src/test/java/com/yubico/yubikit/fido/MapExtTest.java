/*
 * Copyright (C) 2023 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yubico.yubikit.fido;

import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class MapExtTest {
    @Test
    public void nulls() {
        Map<String, Object> l = new HashMap<>();
        Map<String, Object> r = new HashMap<>();

        Assert.assertTrue(MapExt.equals(null, null));
        Assert.assertFalse(MapExt.equals(l, null));
        Assert.assertFalse(MapExt.equals(null, r));
        Assert.assertTrue(MapExt.equals(l, r));
    }

    @Test
    public void types() {
        {
            Map<Long, Object> l = new HashMap<>();
            Map<Long, Object> r = new HashMap<>();

            l.put(1L, "hej");
            r.put(1L, "hej");

            Assert.assertTrue(MapExt.equals(l, r));
        }

        {
            Map<Long, Object> l = new HashMap<>();
            Map<Integer, Object> r = new HashMap<>();

            l.put(1L, "hej");
            r.put(1, "hej");

            Assert.assertFalse(MapExt.equals(l, r));
        }

        {
            Map<String, Integer> l = new HashMap<>();
            Map<String, Long> r = new HashMap<>();

            l.put("l", 1);
            r.put("l", 1L);

            Assert.assertFalse(MapExt.equals(l, r));
        }
    }

    @Test
    public void primitives() {
        Map<Integer, Object> l = new HashMap<>();
        Map<Integer, Object> r = new HashMap<>();

        l.put(1, (byte) 1);
        l.put(2, (short) 10);
        l.put(3, (int) 100);
        l.put(4, (long) 1000L);
        l.put(5, (float) 1.1);
        l.put(6, (double) 1.2);
        l.put(7, (boolean) true);
        l.put(8, (char) 'c');
        l.put(9, (String) "string");

        r.put(1, (byte) 1);
        r.put(2, (short) 10);
        r.put(3, (int) 100);
        r.put(4, (long) 1000L);
        r.put(5, (float) 1.1);
        r.put(6, (double) 1.2);
        r.put(7, (boolean) true);
        r.put(8, (char) 'c');
        r.put(9, (String) "string");

        Assert.assertTrue(MapExt.equals(l, r));

        r.put(8, (char) 'd');

        Assert.assertFalse(MapExt.equals(l, r));
    }

    @Test
    public void sizes() {
        Map<Double, Object> l = new HashMap<>();
        Map<Double, Object> r = new HashMap<>();

        l.put(1.123, (byte) 1);
        r.put(1.123, (byte) 1);

        Assert.assertTrue(MapExt.equals(l, r));

        r.put(1.125, (char) 'd');

        Assert.assertFalse(MapExt.equals(l, r));

        l.put(1.125, (char) 'd');

        Assert.assertTrue(MapExt.equals(l, r));
    }

    @Test
    public void valueTypes() {
        Map<Long, Object> l = new HashMap<>();
        Map<Long, Object> r = new HashMap<>();

        l.put(100L, 1);
        r.put(100L, 1);

        Assert.assertTrue(MapExt.equals(l, r));

        l.put(100L, 1);
        r.put(100L, 1L);

        Assert.assertFalse(MapExt.equals(l, r));

        l.put(100L, 1);
        r.put(100L, null);

        Assert.assertFalse(MapExt.equals(l, r));

        l.put(100L, null);
        r.put(100L, null);

        Assert.assertTrue(MapExt.equals(l, r));
    }

    @Test
    public void arrays() {
        Map<Long, Object> l = new HashMap<>();
        Map<Long, Object> r = new HashMap<>();

        l.put(100L, new byte[]{0, 1, 2});
        r.put(100L, new byte[]{0, 1, 2});

        Assert.assertTrue(MapExt.equals(l, r));

        l.put(200L, new byte[]{0, 2, 3});
        r.put(200L, new byte[]{0, 2, 4});

        Assert.assertFalse(MapExt.equals(l, r));
    }
}