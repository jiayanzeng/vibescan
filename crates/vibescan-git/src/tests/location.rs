use super::*;

#[test]
fn classify_location_matches_monorepo_segment_rules() {
    let cases = [
        (
            "apps/web/.next/static/chunks/x.js",
            "",
            LocationClass::ClientReachable,
        ),
        ("apps/api/.env", "", LocationClass::ServerOnly),
        ("apps/web/.env.local", "", LocationClass::ServerOnly),
        (
            "packages/ui/src/components/Btn.tsx",
            "",
            LocationClass::ClientReachable,
        ),
        ("services/api/index.ts", "", LocationClass::ServerOnly),
        (
            "services/api/src/api/handler.ts",
            "import { NextRequest } from \"next/server\";",
            LocationClass::ServerOnly,
        ),
        (
            "packages/web/src/api/client.ts",
            "export const load = () => fetch('/rest/v1/profiles');",
            LocationClass::ClientReachable,
        ),
        ("apps/web/app/api/route.ts", "", LocationClass::ServerOnly),
        ("apps/web/app/page.tsx", "", LocationClass::ClientReachable),
        (
            "apps/web/.next/server/vendor-chunks/x.js",
            "",
            LocationClass::ServerOnly,
        ),
    ];

    for (path, content, expected) in cases {
        assert_eq!(
            classify_location(path, content.as_bytes()),
            expected,
            "{path}"
        );
    }
}

#[test]
fn classify_location_uses_segments_not_substrings() {
    let cases = [
        ("staticassets/x.js", "", LocationClass::Unknown),
        ("apps/web/src/myenv.ts", "", LocationClass::Unknown),
        ("apps/foo/api-docs/readme.md", "", LocationClass::Unknown),
        (
            "apps/web/app/foo/api/route.ts",
            "",
            LocationClass::ClientReachable,
        ),
    ];

    for (path, content, expected) in cases {
        assert_eq!(
            classify_location(path, content.as_bytes()),
            expected,
            "{path}"
        );
    }
}

#[test]
fn classify_location_preserves_flat_repo_behavior() {
    let cases = [
        ("public/config.js", "", LocationClass::ClientReachable),
        ("app/page.tsx", "", LocationClass::ClientReachable),
        ("pages/index.tsx", "", LocationClass::ClientReachable),
        ("src/app/page.tsx", "", LocationClass::ClientReachable),
        ("src/pages/index.tsx", "", LocationClass::ClientReachable),
        (
            "src/components/Button.tsx",
            "",
            LocationClass::ClientReachable,
        ),
        ("src/client/widget.ts", "", LocationClass::ClientReachable),
        ("src/Button.client.tsx", "", LocationClass::ClientReachable),
        ("dist/bundle.js", "", LocationClass::ClientReachable),
        ("build/assets/app.js", "", LocationClass::ClientReachable),
        (
            ".next/static/chunks/x.js",
            "",
            LocationClass::ClientReachable,
        ),
        (".env", "", LocationClass::ServerOnly),
        (".env.local", "", LocationClass::ServerOnly),
        ("server/index.ts", "", LocationClass::ServerOnly),
        (
            "supabase/functions/ping/index.ts",
            "",
            LocationClass::ServerOnly,
        ),
        ("api/handler.ts", "", LocationClass::ServerOnly),
        (
            "apps/api/index.ts",
            "export const client = true;",
            LocationClass::ServerOnly,
        ),
        (
            "src/api/supabase.ts",
            "export const load = () => fetch('/rest/v1/profiles');",
            LocationClass::ClientReachable,
        ),
        (
            "src/api/handler.ts",
            "import { NextRequest } from \"next/server\";",
            LocationClass::ServerOnly,
        ),
        (
            "src/api/db.ts",
            "import \"node:fs\";",
            LocationClass::ServerOnly,
        ),
        (
            "src/api/actions.ts",
            "'use server';",
            LocationClass::ServerOnly,
        ),
        (
            "src/api/require-db.ts",
            "const crypto = require('node:crypto');",
            LocationClass::ServerOnly,
        ),
        (
            "src/api/env-client.ts",
            "const url = process.env.NEXT_PUBLIC_SUPABASE_URL;",
            LocationClass::ClientReachable,
        ),
        (
            "src/api/node-label.ts",
            "const runtime = 'node:fs';",
            LocationClass::ClientReachable,
        ),
        (
            "src/api/helper.ts",
            "const runtime = myrequire('node:fs');",
            LocationClass::ClientReachable,
        ),
        ("src/lib/util.ts", "", LocationClass::Unknown),
    ];

    for (path, content, expected) in cases {
        assert_eq!(
            classify_location(path, content.as_bytes()),
            expected,
            "{path}"
        );
    }
}

#[test]
fn track_l_classifier_hypotheses_match_architecture_precedence() {
    let cases = [
        ("public/server/config.json", LocationClass::ServerOnly),
        ("app/server/page.tsx", LocationClass::ServerOnly),
        (
            "services/worker/dist/index.js",
            LocationClass::ClientReachable,
        ),
        ("app/api/(admin)/route.ts", LocationClass::ServerOnly),
        (
            "src/app/@modal/(.)photo/page.tsx",
            LocationClass::ClientReachable,
        ),
    ];

    for (path, expected) in cases {
        assert_eq!(classify_location(path, b""), expected, "{path}");
    }
}
