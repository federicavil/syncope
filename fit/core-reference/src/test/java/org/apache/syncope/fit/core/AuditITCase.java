/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.syncope.fit.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.List;
import org.apache.syncope.common.lib.to.AuditEntryTO;
import org.apache.syncope.common.lib.to.GroupTO;
import org.apache.syncope.common.lib.to.PagedResult;
import org.apache.syncope.common.lib.to.UserTO;
import org.apache.syncope.common.rest.api.beans.AuditQuery;
import org.apache.syncope.fit.AbstractITCase;
import org.junit.jupiter.api.Test;

public class AuditITCase extends AbstractITCase {

    private AuditEntryTO query(final String key, final int maxWaitSeconds) {
        int i = 0;
        List<AuditEntryTO> results = List.of();
        do {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
            }

            results = auditService.search(new AuditQuery.Builder().
                    key(key).orderBy("event_date desc").page(1).size(1).build()).getResult();

            i++;
        } while (results.isEmpty() && i < maxWaitSeconds);
        if (results.isEmpty()) {
            fail("Timeout when executing query for key " + key);
        }

        return results.get(0);
    }

    @Test
    public void findByUser() {
        UserTO userTO = createUser(UserITCase.getUniqueSample("audit@syncope.org")).getEntity();
        assertNotNull(userTO.getKey());

        AuditEntryTO entry = query(userTO.getKey(), 50);
        assertEquals(userTO.getKey(), entry.getKey());
        userService.delete(userTO.getKey());
    }

    @Test
    public void findByGroup() {
        GroupTO groupTO = createGroup(GroupITCase.getBasicSample("AuditGroup")).getEntity();
        assertNotNull(groupTO.getKey());

        AuditEntryTO entry = query(groupTO.getKey(), 50);
        assertEquals(groupTO.getKey(), entry.getKey());
        groupService.delete(groupTO.getKey());
    }
}