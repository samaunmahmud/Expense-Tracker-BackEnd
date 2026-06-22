package com.expensetracker.expensetracker.controller;

import com.expensetracker.expensetracker.security.UserPrincipal;
import com.expensetracker.expensetracker.service.PlaidService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/plaid")
@RequiredArgsConstructor
public class PlaidController {

    private final PlaidService plaidService;

    @PostMapping("/link-token")
    public Map createLinkToken(@AuthenticationPrincipal UserPrincipal principal) {
        return plaidService.createLinkToken(String.valueOf(principal.getUser().getId()));
    }

    @PostMapping("/exchange-token")
    public Map exchangeToken(@RequestBody Map<String, String> request) {
        String publicToken = request.get("public_token");
        return plaidService.exchangePublicToken(publicToken);
    }
}