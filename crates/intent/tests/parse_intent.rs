use intent::{parse_intent, Intent, ParsedIntent};
use protocol::MemberRole;

fn parse(text: &str) -> Option<ParsedIntent> {
    parse_intent(text)
}

// ── Positive cases — one per verb, plus a phrasing variant each ────────────

#[test]
fn pause_variants() {
    assert_eq!(
        parse("pause session").map(|p| p.intent),
        Some(Intent::Pause)
    );
    assert_eq!(
        parse("please pause the session").map(|p| p.intent),
        Some(Intent::Pause)
    );
    assert_eq!(parse("halt session").map(|p| p.intent), Some(Intent::Pause));
    assert_eq!(
        parse("suspend the session").map(|p| p.intent),
        Some(Intent::Pause)
    );
    assert_eq!(
        parse("PAUSE SESSION").map(|p| p.intent),
        Some(Intent::Pause),
        "case-insensitive"
    );
}

#[test]
fn resume_variants() {
    assert_eq!(
        parse("resume session").map(|p| p.intent),
        Some(Intent::Resume)
    );
    assert_eq!(
        parse("please reactivate the session").map(|p| p.intent),
        Some(Intent::Resume)
    );
    assert_eq!(
        parse("unpause session").map(|p| p.intent),
        Some(Intent::Resume)
    );
}

#[test]
fn archive_variants() {
    assert_eq!(
        parse("archive session").map(|p| p.intent),
        Some(Intent::Archive)
    );
    assert_eq!(
        parse("please archive the session").map(|p| p.intent),
        Some(Intent::Archive)
    );
}

#[test]
fn approve_deny_claim() {
    assert_eq!(
        parse("approve this").map(|p| p.intent),
        Some(Intent::Approve)
    );
    assert_eq!(parse("approve it").map(|p| p.intent), Some(Intent::Approve));
    assert_eq!(
        parse("please approve").map(|p| p.intent),
        Some(Intent::Approve)
    );
    assert_eq!(parse("deny this").map(|p| p.intent), Some(Intent::Deny));
    assert_eq!(parse("reject it").map(|p| p.intent), Some(Intent::Deny));
    assert_eq!(parse("claim this").map(|p| p.intent), Some(Intent::Claim));
    assert_eq!(
        parse("please claim it").map(|p| p.intent),
        Some(Intent::Claim)
    );
}

#[test]
fn invite_with_role_and_invitee() {
    match parse("invite alice as owner") {
        Some(ParsedIntent {
            intent:
                Intent::Invite {
                    role,
                    invitee,
                    ttl_secs: _,
                },
            target_session,
        }) => {
            assert_eq!(role, MemberRole::Owner);
            assert_eq!(invitee.as_deref(), Some("alice"));
            assert_eq!(target_session, None);
        }
        other => panic!("expected Invite, got {other:?}"),
    }
}

#[test]
fn invite_defaults_to_collaborator_without_as_clause() {
    match parse("invite bob") {
        Some(ParsedIntent {
            intent: Intent::Invite { role, invitee, .. },
            ..
        }) => {
            assert_eq!(role, MemberRole::Collaborator);
            assert_eq!(invitee.as_deref(), Some("bob"));
        }
        other => panic!("expected Invite, got {other:?}"),
    }
}

#[test]
fn invite_no_invitee_still_matches() {
    match parse("please invite") {
        Some(ParsedIntent {
            intent:
                Intent::Invite {
                    role,
                    invitee,
                    ttl_secs: _,
                },
            target_session,
        }) => {
            assert_eq!(role, MemberRole::Collaborator);
            assert_eq!(invitee, None);
            assert_eq!(target_session, None);
        }
        other => panic!("expected Invite, got {other:?}"),
    }
}

#[test]
fn invite_extracts_target_session_from_to_clause() {
    // The user's own reported case: "to <session>" must stop the invitee
    // name AND surface as target_session, not get silently dropped.
    match parse("invite bob to roman-room1") {
        Some(ParsedIntent {
            intent:
                Intent::Invite {
                    role,
                    invitee,
                    ttl_secs: _,
                },
            target_session,
        }) => {
            assert_eq!(role, MemberRole::Collaborator);
            assert_eq!(invitee.as_deref(), Some("bob"));
            assert_eq!(target_session.as_deref(), Some("roman-room1"));
        }
        other => panic!("expected Invite, got {other:?}"),
    }
    // Order-independent: role clause before the target-session clause.
    match parse("invite bob as owner to roman-room1") {
        Some(ParsedIntent {
            intent:
                Intent::Invite {
                    role,
                    invitee,
                    ttl_secs: _,
                },
            target_session,
        }) => {
            assert_eq!(role, MemberRole::Owner);
            assert_eq!(invitee.as_deref(), Some("bob"));
            assert_eq!(target_session.as_deref(), Some("roman-room1"));
        }
        other => panic!("expected Invite, got {other:?}"),
    }
    // And the other order: target-session clause before role.
    match parse("invite bob to roman-room1 as owner") {
        Some(ParsedIntent {
            intent:
                Intent::Invite {
                    role,
                    invitee,
                    ttl_secs: _,
                },
            target_session,
        }) => {
            assert_eq!(role, MemberRole::Owner);
            assert_eq!(invitee.as_deref(), Some("bob"));
            assert_eq!(target_session.as_deref(), Some("roman-room1"));
        }
        other => panic!("expected Invite, got {other:?}"),
    }
}

#[test]
fn transfer_ownership_variants() {
    match parse("transfer ownership to bob") {
        Some(ParsedIntent {
            intent: Intent::TransferOwnership { to },
            target_session,
        }) => {
            assert_eq!(to, "bob");
            assert_eq!(target_session, None);
        }
        other => panic!("expected TransferOwnership, got {other:?}"),
    }
    match parse("please transfer to alice") {
        Some(ParsedIntent {
            intent: Intent::TransferOwnership { to },
            ..
        }) => assert_eq!(to, "alice"),
        other => panic!("expected TransferOwnership, got {other:?}"),
    }
    match parse("transfer bob") {
        Some(ParsedIntent {
            intent: Intent::TransferOwnership { to },
            ..
        }) => assert_eq!(to, "bob"),
        other => panic!("expected TransferOwnership, got {other:?}"),
    }
}

#[test]
fn transfer_with_no_recipient_does_not_match() {
    // "transfer ownership" alone matches the verb-phrase Fst (0-length
    // remainder), but extract_transfer correctly refuses to invent a
    // recipient — parse_intent must surface that as None, not panic or
    // fabricate a target.
    assert!(parse("transfer ownership").is_none());
}

#[test]
fn transfer_extracts_target_session_via_in_clause() {
    // "to" is taken by the recipient on transfer, so target-session uses
    // "in" instead — both orderings.
    match parse("transfer ownership to bob in roman-room1") {
        Some(ParsedIntent {
            intent: Intent::TransferOwnership { to },
            target_session,
        }) => {
            assert_eq!(to, "bob");
            assert_eq!(target_session.as_deref(), Some("roman-room1"));
        }
        other => panic!("expected TransferOwnership, got {other:?}"),
    }
    match parse("transfer ownership in roman-room1 to bob") {
        Some(ParsedIntent {
            intent: Intent::TransferOwnership { to },
            target_session,
        }) => {
            assert_eq!(to, "bob");
            assert_eq!(target_session.as_deref(), Some("roman-room1"));
        }
        other => panic!("expected TransferOwnership, got {other:?}"),
    }
}

#[test]
fn slot_less_verbs_extract_target_session_via_in_clause() {
    assert_eq!(
        parse("pause session in roman-room1")
            .and_then(|p| p.target_session)
            .as_deref(),
        Some("roman-room1"),
    );
    assert_eq!(
        parse("archive session in roman-room1")
            .and_then(|p| p.target_session)
            .as_deref(),
        Some("roman-room1"),
    );
    assert_eq!(
        parse("approve this in roman-room1")
            .and_then(|p| p.target_session)
            .as_deref(),
        Some("roman-room1"),
    );
    // No "in" clause — target_session is None, meaning "the current session".
    assert_eq!(parse("pause session").and_then(|p| p.target_session), None);
}

#[test]
fn invite_extracts_duration_as_ttl() {
    match parse("invite bob@gmail.com 1 day") {
        Some(ParsedIntent {
            intent: Intent::Invite {
                invitee, ttl_secs, ..
            },
            ..
        }) => {
            assert_eq!(invitee.as_deref(), Some("bob@gmail.com"));
            assert_eq!(ttl_secs, Some(86_400));
        }
        other => panic!("expected Invite, got {other:?}"),
    }
    match parse("invite bob 15 minutes") {
        Some(ParsedIntent {
            intent: Intent::Invite {
                invitee, ttl_secs, ..
            },
            ..
        }) => {
            assert_eq!(invitee.as_deref(), Some("bob"));
            assert_eq!(ttl_secs, Some(900));
        }
        other => panic!("expected Invite, got {other:?}"),
    }
    // Duration clause interleaved with role/target-session clauses — must
    // not get swallowed into either.
    match parse("invite bob as owner 2 hours") {
        Some(ParsedIntent {
            intent:
                Intent::Invite {
                    role,
                    invitee,
                    ttl_secs,
                    ..
                },
            ..
        }) => {
            assert_eq!(role, MemberRole::Owner);
            assert_eq!(invitee.as_deref(), Some("bob"));
            assert_eq!(ttl_secs, Some(7_200));
        }
        other => panic!("expected Invite, got {other:?}"),
    }
    // No duration clause — ttl_secs is None (caller falls back to a default).
    match parse("invite bob") {
        Some(ParsedIntent {
            intent: Intent::Invite { ttl_secs, .. },
            ..
        }) => assert_eq!(ttl_secs, None),
        other => panic!("expected Invite, got {other:?}"),
    }
}

#[test]
fn goto_variants() {
    for text in [
        "go to roman-room1",
        "goto roman-room1",
        "jump to roman-room1",
        "switch to roman-room1",
        "please go to roman-room1",
    ] {
        match parse(text) {
            Some(ParsedIntent {
                intent: Intent::Navigate,
                target_session,
            }) => {
                assert_eq!(
                    target_session.as_deref(),
                    Some("roman-room1"),
                    "for input {text:?}"
                );
            }
            other => panic!("expected Navigate for {text:?}, got {other:?}"),
        }
    }
}

#[test]
fn goto_with_no_session_name_does_not_match() {
    // The whole point of Navigate is a destination — an empty one means
    // this isn't a real navigation command, not a Navigate to nowhere.
    assert!(parse("go to").is_none());
    assert!(parse("goto").is_none());
}

#[test]
fn attach_variants() {
    match parse("attach agent-x 15 minutes") {
        Some(ParsedIntent {
            intent: Intent::AttachAgent { name, ttl_secs },
            target_session,
        }) => {
            assert_eq!(name.as_deref(), Some("agent-x"));
            assert_eq!(ttl_secs, Some(900));
            assert_eq!(target_session, None);
        }
        other => panic!("expected AttachAgent, got {other:?}"),
    }
    match parse("please attach fs-agent") {
        Some(ParsedIntent {
            intent: Intent::AttachAgent { name, ttl_secs },
            ..
        }) => {
            assert_eq!(name.as_deref(), Some("fs-agent"));
            assert_eq!(ttl_secs, None);
        }
        other => panic!("expected AttachAgent, got {other:?}"),
    }
    // No name at all is still a valid (if sparse) AttachAgent — same
    // "bare verb still matches" convention as invite's `invite_no_invitee_
    // still_matches`; the frontend/modal already defaults the Agent ID
    // field, so there's nothing to fabricate here either.
    match parse("attach") {
        Some(ParsedIntent {
            intent: Intent::AttachAgent { name, ttl_secs },
            ..
        }) => {
            assert_eq!(name, None);
            assert_eq!(ttl_secs, None);
        }
        other => panic!("expected AttachAgent, got {other:?}"),
    }
}

#[test]
fn attach_extracts_target_session_via_in_clause() {
    match parse("attach agent-x in roman-room1 15 minutes") {
        Some(ParsedIntent {
            intent: Intent::AttachAgent { name, ttl_secs },
            target_session,
        }) => {
            assert_eq!(name.as_deref(), Some("agent-x"));
            assert_eq!(ttl_secs, Some(900));
            assert_eq!(target_session.as_deref(), Some("roman-room1"));
        }
        other => panic!("expected AttachAgent, got {other:?}"),
    }
}

#[test]
fn adversarial_attach_only_matches_as_the_leading_word() {
    // Same shape as the goto/switch-to case: "attach" mid-sentence can't
    // anchor a match (matcher only ever walks from token 0)...
    assert!(parse("please remember to attach the file before you send it").is_none());
    // ...but "attach" AS the leading word of otherwise-ordinary text is a
    // known, accepted false-positive shape, same reasoning as "switch to a
    // different plan" above: it's inert until the user explicitly selects
    // the resulting Command entry, and even then only opens the Attach
    // Agent modal pre-filled — it never mints a token on its own.
    match parse("attach the file to your reply") {
        Some(ParsedIntent {
            intent: Intent::AttachAgent { name, .. },
            ..
        }) => {
            assert_eq!(name.as_deref(), Some("the file to your reply"));
        }
        other => panic!("expected the documented false-positive shape, got {other:?}"),
    }
}

// ── Adversarial — real chat-shaped sentences that must NOT parse as a
//    command. This set matters as much as the positive cases: a false
//    positive here means an ordinary message gets silently reinterpreted
//    as a governance action, which is the actual failure mode this
//    architecture exists to avoid (see lib.rs's doc comment). ─────────────

#[test]
fn adversarial_ordinary_chat_does_not_match() {
    let ordinary = [
        "hey can someone check on this session later",
        "I paused for a moment before responding",
        "the session was archived last week by mistake",
        "this looks approved to me but let's double check",
        "who's going to claim credit for this",
        "we should invite more people to the next meeting sometime",
        "resuming work on the report tomorrow",
        "denying that this is even a problem",
        "",
        "   ",
        "session",
        "please",
    ];
    for text in ordinary {
        assert!(parse(text).is_none(), "false positive on: {text:?}");
    }
}

#[test]
fn adversarial_partial_phrase_does_not_match() {
    // Missing the required literal anchor ("session") — must not match
    // just because "pause" appears somewhere in the text.
    assert!(parse("pause").is_none());
    assert!(parse("pause the").is_none());
    assert!(parse("session pause").is_none(), "wrong word order");
}

#[test]
fn adversarial_goto_words_only_match_as_the_leading_phrase() {
    // "go"/"jump"/"switch" are common enough English words that they must
    // NOT trigger a match unless they're literally the first word(s) of the
    // input, immediately followed by "to" — matching.longest_matching_prefix
    // only ever walks from token 0, so a verb-shaped word appearing
    // mid-sentence can't accidentally anchor a match.
    assert!(parse("I need to go check on that session").is_none());
    assert!(parse("let's switch topics for a second").is_none());
    assert!(parse("can we jump on a call about this session").is_none());
    // "switch to <topic>" as an ordinary non-navigation sentence IS a known,
    // accepted false-positive shape (see slots.rs's marker-word doc
    // comment): it parses as Navigate{target_session: Some("a different
    // plan")}, but that's inert until (a) target-session resolution finds a
    // real session by that name (server-side, membership-scoped) and (b)
    // the user explicitly selects the resulting Command entry — never
    // auto-executed. Documented here as a deliberate tradeoff, not
    // overlooked.
    match parse("switch to a different plan") {
        Some(ParsedIntent {
            intent: Intent::Navigate,
            target_session,
        }) => {
            assert_eq!(target_session.as_deref(), Some("a different plan"));
        }
        other => panic!("expected the documented false-positive shape, got {other:?}"),
    }
}

#[test]
fn adversarial_unknown_leading_word_does_not_match() {
    // A word that appears nowhere in any grammar's vocabulary sits before
    // the verb — this must not somehow still match the tail as if the
    // unknown word weren't there.
    assert!(parse("wellactually pause session").is_none());
}
