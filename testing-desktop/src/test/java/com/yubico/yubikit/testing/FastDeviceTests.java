/*
 * Copyright (C) 2024 Yubico.
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

package com.yubico.yubikit.testing;

import org.junit.experimental.categories.Categories;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * These tests are here to make testing a bit faster and exclude following:
 * <ul>
 *     <li>{@link SlowTest}</li>
 *     <li>{@link PinUvAuthProtocolV1Test}</li>
 *     <li>{@link AlwaysManualTest}</li>
 * </ul>
 */
@RunWith(Categories.class)
@Suite.SuiteClasses(DeviceTests.class)
@Categories.ExcludeCategory({
        SlowTest.class,
        PinUvAuthProtocolV1Test.class,
        AlwaysManualTest.class
})
public class FastDeviceTests {
}
