package com.casinthecloud;

import org.apereo.cas.CipherExecutor;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.ticket.ExpirationPolicy;
import org.apereo.cas.ticket.UniqueTicketIdGenerator;
import org.apereo.cas.ticket.factory.DefaultTicketGrantingTicketFactory;

import java.io.Serializable;
import java.util.List;

/**
 * custo for back channel logout
 */
public class MyDefaultTicketGrantingTicketFactory extends DefaultTicketGrantingTicketFactory {

    public MyDefaultTicketGrantingTicketFactory(final UniqueTicketIdGenerator ticketGrantingTicketUniqueTicketIdGenerator,
                                                final ExpirationPolicy ticketGrantingTicketExpirationPolicy,
                                                final CipherExecutor<Serializable, String> cipherExecutor) {
        super(ticketGrantingTicketUniqueTicketIdGenerator, ticketGrantingTicketExpirationPolicy, cipherExecutor);
    }

    @Override
    protected String produceTicketIdentifier(final Authentication authentication) {
        final List<String> sessionIndex = (List<String>) authentication.getPrincipal().getAttributes().get("sessionindex");
        if (sessionIndex != null && !sessionIndex.isEmpty()) {
            return sessionIndex.get(0);
        }

        return super.produceTicketIdentifier(authentication);
    }
}
