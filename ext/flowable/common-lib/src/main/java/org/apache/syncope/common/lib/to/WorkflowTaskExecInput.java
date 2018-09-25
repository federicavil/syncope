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
package org.apache.syncope.common.lib.to;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.HashMap;
import java.util.Map;
import javax.ws.rs.PathParam;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.apache.syncope.common.lib.AbstractBaseBean;
import org.apache.syncope.common.lib.jaxb.XmlGenericMapAdapter;

@XmlRootElement(name = "workflowTaskExecInput")
@XmlType
public class WorkflowTaskExecInput extends AbstractBaseBean {

    private static final long serialVersionUID = 8060283119070901756L;

    private String userKey;

    @XmlJavaTypeAdapter(XmlGenericMapAdapter.class)
    private final Map<String, String> variables = new HashMap<>();

    public String getUserKey() {
        return userKey;
    }

    @PathParam("userKey")
    public void setUserKey(final String userKey) {
        this.userKey = userKey;
    }

    @JsonProperty
    public Map<String, String> getVariables() {
        return variables;
    }
}
