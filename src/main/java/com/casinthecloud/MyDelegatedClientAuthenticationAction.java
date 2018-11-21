package com.casinthecloud;

import org.apereo.cas.CentralAuthenticationService;
import org.apereo.cas.audit.AuditableExecution;
import org.apereo.cas.authentication.AuthenticationServiceSelectionPlan;
import org.apereo.cas.authentication.AuthenticationSystemSupport;
import org.apereo.cas.authentication.adaptive.AdaptiveAuthenticationPolicy;
import org.apereo.cas.logout.LogoutManager;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.pac4j.logout.RequestSloException;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.web.DelegatedClientWebflowManager;
import org.apereo.cas.web.flow.DelegatedClientAuthenticationAction;
import org.apereo.cas.web.flow.resolver.CasDelegatingWebflowEventResolver;
import org.apereo.cas.web.flow.resolver.CasWebflowEventResolver;
import org.apereo.cas.web.pac4j.DelegatedSessionCookieManager;

import lombok.extern.slf4j.Slf4j;
import org.pac4j.core.client.BaseClient;
import org.pac4j.core.client.Clients;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.profile.CommonProfile;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.webflow.execution.Event;

import java.io.IOException;

/**
 * custo for back channel logout
 */
@Slf4j
public class MyDelegatedClientAuthenticationAction extends DelegatedClientAuthenticationAction {

    @Autowired
    @Qualifier("logoutManager")
    private LogoutManager logoutManager;

    @Autowired
    @Qualifier("centralAuthenticationService")
    private CentralAuthenticationService centralAuthenticationService;

    public MyDelegatedClientAuthenticationAction(final CasDelegatingWebflowEventResolver initialAuthenticationAttemptWebflowEventResolver,
                                                 final CasWebflowEventResolver serviceTicketRequestWebflowEventResolver,
                                                 final AdaptiveAuthenticationPolicy adaptiveAuthenticationPolicy,
                                                 final Clients clients,
                                                 final ServicesManager servicesManager,
                                                 final AuditableExecution delegatedAuthenticationPolicyEnforcer,
                                                 final DelegatedClientWebflowManager delegatedClientWebflowManager,
                                                 final DelegatedSessionCookieManager delegatedSessionCookieManager,
                                                 final AuthenticationSystemSupport authenticationSystemSupport,
                                                 final String localeParamName,
                                                 final String themeParamName,
                                                 final AuthenticationServiceSelectionPlan authenticationRequestServiceSelectionStrategies) {
        super(initialAuthenticationAttemptWebflowEventResolver, serviceTicketRequestWebflowEventResolver,
                adaptiveAuthenticationPolicy, clients, servicesManager, delegatedAuthenticationPolicyEnforcer,
                delegatedClientWebflowManager, delegatedSessionCookieManager, authenticationSystemSupport, localeParamName,
                themeParamName, authenticationRequestServiceSelectionStrategies);
    }

    @Override
    protected Event handleException(final J2EContext webContext, final BaseClient<Credentials, CommonProfile> client, final Exception e) {
        if (e instanceof RequestSloException) {

            //custo:
            final RequestSloException ex = (RequestSloException) e;
            final boolean backChannel = !ex.isFrontChannel();
            if (backChannel) {
                final TicketGrantingTicket tgt = centralAuthenticationService.getTicket(ex.getKey(), TicketGrantingTicket.class);
                logoutManager.performLogout(tgt);
            }

            try {
                webContext.getResponse().sendRedirect("logout");
            } catch (final IOException ioe) {
                throw new IllegalArgumentException("Unable to call logout", ioe);
            }

            return stopWebflow();
        } else {
            LOGGER.info(e.getMessage(), e);
            throw new IllegalArgumentException("Delegated authentication has failed with client " + client.getName());
        }
    }
}
