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
package org.apache.syncope.client.console.pages;

import org.apache.commons.lang3.StringUtils;
import org.apache.syncope.client.console.panels.ResourceDirectoryPanel;
import org.apache.syncope.client.console.wizards.WizardMgtPanel;
import org.apache.syncope.client.console.wizards.resources.ResourceWizardBuilder;
import org.apache.syncope.client.ui.commons.markup.html.form.AjaxTextFieldPanel;
import org.apache.syncope.common.lib.to.ResourceTO;
import org.apache.wicket.PageReference;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.ajax.markup.html.form.AjaxButton;
import org.apache.wicket.event.Broadcast;
import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.panel.Panel;
import org.apache.wicket.model.Model;
import java.io.Serializable;

public class Resources extends Panel {

    private static final long serialVersionUID = 7240865652350993779L;

    private final WizardMgtPanel<Serializable> resourceDirectoryPanel;

    public Resources(final String id, final PageReference pageRef) {
        super(id);

        Model<String> keywordModel = new Model<>(StringUtils.EMPTY);

        WebMarkupContainer searchBoxContainer = new WebMarkupContainer("searchBox");
        add(searchBoxContainer);

        Form<?> form = new Form<>("form");
        searchBoxContainer.add(form);

        AjaxTextFieldPanel filter = new AjaxTextFieldPanel("filter", "filter", keywordModel, true);
        form.add(filter.hideLabel().setOutputMarkupId(true));

        AjaxButton search = new AjaxButton("search") {

            private static final long serialVersionUID = 8390605330558248736L;

            @Override
            protected void onSubmit(final AjaxRequestTarget target) {
                send(Resources.this, Broadcast.DEPTH,
                        new ResourceDirectoryPanel.ResourceSearchEvent(target, keywordModel.getObject()));
            }
        };
        search.setOutputMarkupId(true);
        form.add(search);
        form.setDefaultButton(search);

        resourceDirectoryPanel =
                new ResourceDirectoryPanel.Builder(pageRef).
                        addNewItemPanelBuilder(new ResourceWizardBuilder(
                                new ResourceTO(), pageRef), true).
                        build("resourceDirectoryPanel");
        resourceDirectoryPanel.setOutputMarkupId(true);

        add(resourceDirectoryPanel);
    }
}
