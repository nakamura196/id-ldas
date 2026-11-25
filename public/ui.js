// Shared page chrome: header (site name, navigation, language and theme switches) and footer.
// Markup uses data-i18n="key" (text) or data-i18n-html="key" (trusted markup from this file only).

const STRINGS = {
  ja: {
    'switch.lang': 'English',
    'nav.home': 'ホーム', 'nav.verify': 'VC を検証', 'nav.admin': '管理', 'nav.menu': 'メニュー', 'nav.close': '閉じる',
    'footer.about': '練習用の ID サーバです。DID / VC とパスキー、ORCID・GakuNin RDM・メール認証、ウォレットの結びつけを試すために作りました。',
    'footer.did': 'このサーバの DID 文書（公開鍵）',
    'footer.by': '運営: 中村 覚',
    'theme.auto': '表示: 自動', 'theme.light': '表示: ライト', 'theme.dark': '表示: ダーク',

    'home.heroTitle': 'LDAS ID — デジタル会員証',
    'home.lead': 'ORCID・GakuNin RDM・メールアドレスでサインインし、連携先のデータスペースやアプリで使えるデジタル会員証（VC）を発行・管理できます。',
    'home.ctaPrimary': 'サインインしてはじめる',
    'home.ctaVerify': '証明書を検証する',
    'home.stepsTitle': '使いかた（3 ステップ）',
    'home.step1Title': 'サインインする',
    'home.step1Text': 'ORCID・GakuNin RDM・メールアドレス（6 桁コード）のいずれかでログインします。生メールアドレスはサーバに保存しません。',
    'home.step2Title': '必要に応じて所属を確認',
    'home.step2Text': '大学や機関の特典を使う場合は、所属メールの確認コードまたは GakuNin RDM で所属を証明できます。',
    'home.step3Title': '連携先アプリで使う',
    'home.step3Text': '対応アプリからログインすると、渡す項目（氏名・所属機関など）を毎回選んでから会員証を提示できます。',
    'home.techNote': '開発者・技術仕様（W3C VC / SD-JWT / OID4VP / OpenAPI 3.1）',
    'home.accountTitle': 'アカウント管理',
    'home.accountLead': '所属の確認、会員証（VC）の発行・失効、パスキーの追加を行えます。',
    'home.memberActionsTitle': '会員証（VC）とアカウント設定',
    'home.walletOptionalSummary': 'Web3 ウォレットを結びつける（Clio-X など対応アプリを使う方のみ・任意）',
    'home.new': 'はじめての方',
    'home.newText': 'ORCID、GakuNin RDM（学認）、またはメールアドレス（6 桁の確認コード・生アドレス非保存）でサインインしてください。そのまま会員証を受け取れます。',
    'home.orcid': 'ORCID でサインイン',
    'home.returning': 'パスキーを登録済みの方',
    'home.passkeyLogin': 'パスキーでログイン',
    'home.wallet': 'ウォレット',
    'home.affiliation': '確認済み所属',
    'home.affilTitle': '所属機関・メールドメインの確認（大学・企業など）',
    'home.affilDesc': '所属先のメールアドレスに届く 6 桁コード、または GakuNin RDM（学認）連携で確認できます。メールアドレス本体は保存されず、ドメインと所属名だけが選択的開示の対象になります。',
    'home.emailPlaceholder': '例: name@example.ac.jp',
    'home.sendCode': '確認コードを送る',
    'home.codePlaceholder': '6 桁のコード',
    'home.verifyCode': 'コードを確認',
    'home.grdmLink': 'GakuNin RDM（学認）で所属を確認',
    'home.verifiedBadge': '✓ 確認済み',
    'home.reverifyAffil': '別の所属・メールで再確認する',
    'home.methodGrdm': 'GakuNin RDM（学認）',
    'home.methodEmail': 'メール確認コード',
    'home.affilVerifiedHeadline': '✓ 確認済み: {0}{1}',
    'home.affilVerifiedMeta': '確認方法: {0} / 確認日時: {1}',
    'home.none': '（未登録）',
    'home.admin': '管理画面',
    'home.noteTitle': 'ウォレットを結びつける前に',
    'home.note1': '<strong>このためだけの新しいウォレットを使ってください。</strong>お金や大事な資産の入ったウォレットは使わないでください。MetaMask ではアカウントを無料で何個でも作れます。',
    'home.note2': '結びつけると、「あなたの氏名・識別子 = このアドレス」という対応がこのサイトに記録されます。会員証を見せた相手にも伝わります。チェーン上の記録は誰でも見られるので、このアドレスでの行動は、あなたの名前と結びついて見えるようになります。',
    'home.note3': 'このサイトが保存するのはアドレスだけです。秘密の鍵や残高は受け取りません。',
    'home.note4': '求めるのは、短い文への署名だけです。お金は動きません。もし送金や「取引の承認」を求める画面が出たら、押さずに閉じてください。',
    'home.link': 'MetaMask のウォレットを結びつける',
    'home.relink': '別のウォレットに付け替える',
    'home.issue': '会員証（VC）を発行する',
    'home.revokeSelf': '発行済み VC を今すぐ無効化（緊急失効）',
    'home.revokeConfirm': 'これまでに発行した自分の会員証（VC）をすべて失効リストに登録します。よろしいですか？（直後に新しい VC を再発行できます）',
    'home.addPasskey': 'この端末にパスキーを追加',
    'home.logout': 'ログアウト',
    'msg.revokedSelf': '旧 VC（index={0}）を失効リストに登録しました。新しい発行枠は index={1} です。必要に応じて再発行してください。',
    'home.vcTitle': '発行された VC（JWT 形式）',
    'home.vcText': 'この文字列が「証明書」本体です。<a id="toVerify" href="/verify">検証ページ</a>で、この ID サーバに問い合わせずに本物か確かめられます。',
    'home.payload': '中身',
    'home.didDoc': 'このサーバの DID 文書（公開鍵）',
    'home.toVerify': 'VC を検証する',
    'home.returnBannerTitle': '外部アプリとの連携リクエスト',
    'home.returnBannerText': '連携先 {0} があなたの会員証（VC）の提示を求めています。内容を確認のうえ、問題なければ下のボタンで証明書を発行して戻ってください。',
    'home.returnApprove': '会員証（VC）を発行して連携先へ戻る',
    'home.returnCancel': '連携をやめる',
    'home.returnInvalid': '指定された戻り先 URL（return_to）は許可対象外のため無視しました。',
    'home.returnLoginHint': '連携先 {0} へ戻るには、まず ORCID・GakuNin RDM・メールアドレス、またはパスキーでログインしてください。',

    'login.title': 'LDAS ID にサインイン',
    'login.lead': 'ORCID・GakuNin RDM・メールアドレス、またはパスキーでサインインします。',
    'login.nextHint': 'サインインが完了すると、続けて連携先アプリへの認可画面に進みます。',

    'authz.title': 'このアプリに情報を渡しますか？',
    'authz.lead': '連携先アプリに渡す項目を確認してください。任意項目はチェックを外して隠せます。',
    'authz.requestText': '共有する項目を選んで「許可して戻る」を押してください。',
    'authz.claimName': '氏名',
    'authz.claimMember': '所属（会員資格）',
    'authz.claimAffiliation': '所属機関（affiliation）',
    'authz.claimEmailDomain': 'メールドメイン（emailDomain）',
    'authz.claimIssuer': '発行者 DID',
    'authz.required': '必須',
    'authz.optional': '任意',
    'authz.techSummary': '技術情報（OID4VP / SD-JWT）を表示',
    'authz.approve': '許可してアプリへ戻る',
    'authz.cancel': 'キャンセル',
    'authz.switchAccount': '別のアカウントを使う',
    'authz.missingReturn': '戻り先 URL（return_to）が指定されていません。連携先アプリのログインボタンから開いてください。',
    'authz.clientMismatch': '依頼元（client_id）と戻り先（redirect_uri）が一致しないため、中止しました。連携先アプリの管理者にお知らせください。',
    'status.pending': '確認待ちです。',
    'status.approved': '会員証を発行できます。',
    'status.verified': '本人確認済みです。会員証を発行できます。',
    'status.rejected': '利用が止められています。管理者にお問い合わせください。',
    'msg.passkeyAdded': 'パスキーを追加しました。次からは指紋・顔認証でログインできます。',
    'msg.passkeyFailed': '追加できませんでした: {0}',
    'msg.noMetaMask': 'MetaMask が見つかりません',
    'msg.linked': 'ウォレット {0} を結びつけました。会員証を発行し直してください。',
    'msg.linkFailed': '結びつけられませんでした: {0}',
    'msg.loggedIn': 'ログインしました。',
    'msg.loginFailed': 'ログインできませんでした: {0}',
    'msg.orcidCancelled': 'ORCID でのサインインが取り消されました。',
    'msg.codeSent': '確認コードを送信しました（判定ドメイン: {0} / 所属: {1}）。10 分以内に入力してください。',
    'msg.affilVerified': '所属を確認しました: {0} ({1})。必要に応じて VC を再発行してください。',
    'msg.grdmLinked': 'GakuNin RDM（学認）から所属を確認しました。',
    'msg.grdmCancelled': 'GakuNin RDM との連携が取り消されました。',
    'msg.grdmUnconfigured': 'GakuNin RDM 連携はまだサーバに設定されていません。',

    'verify.title': 'VC を検証する',
    'verify.lead': 'ここでの検証は<strong>すべてブラウザの中</strong>で行います。ID サーバの DB には問い合わせません。使うのは、発行者が公開している DID 文書（公開鍵）だけです。cliox などのアプリも、同じ手順で確かめられます。',
    'verify.placeholder': 'eyJ... で始まる VC（JWT）を貼り付け',
    'verify.go': '検証する',
    'verify.holderTitle': 'この会員証を出した人は、本当に持ち主か',
    'verify.holderText': '署名が正しくても、会員証の文字列は写せます。この会員証はウォレット <code id="holderAddr"></code> についてのものです。出した人にそのウォレットで使い捨ての文に署名してもらい、署名した人が同じウォレットか確かめます（ブラウザの中だけで行います）。',
    'verify.challenge': 'MetaMask で署名してもらう',
    'verify.back': 'LDAS ID に戻る',
    'step.header': 'ヘッダを読む: 署名方式 {0}、鍵 {1}',
    'step.mismatch': '鍵の持ち主 ({0}) と発行者 ({1}) が一致しません',
    'step.issuer': '発行者: {0}',
    'step.didDoc': 'DID 文書を取得: {0}',
    'step.noKey': 'DID 文書に、この鍵が載っていません',
    'step.notAssertion': 'この鍵は証明書の署名用に指定されていません',
    'step.keyFound': 'DID 文書の中に、署名用の公開鍵が見つかりました',
    'step.sigOk': '署名は正しく、有効期限内です。改ざんされていません',
    'step.statusOk': '失効リスト ({0}、index={1}) を確認: 有効（失効していません）',
    'step.statusRevoked': '失効リスト ({0}、index={1}) を確認: この証明書は失効（取り消し済み）です',
    'step.conclusion': '結論: {0} が「{1}（{2}）は {3} の会員」と証明しています（{4} まで有効）',
    'step.evidence': '発行者がどう確かめたか: {0}',
    'step.unbound': 'この会員証はウォレットに結びついていません。文字列を持っている人なら誰でも出せます',
    'step.failed': '検証できませんでした: {0}',
    'holder.ok': '署名したのは {0}。会員証のウォレットと一致します。この人が持ち主です。',
    'holder.ng': '署名したのは {0}。会員証のウォレット（{1}）と違います。持ち主ではありません。',
    'holder.failed': '確かめられませんでした: {0}',

    'admin.title': '利用者',
    'admin.lead': 'サインインした人の一覧です。ORCID・GakuNin RDM・メールアドレスでサインインすると自動で使えるようになります。おかしな使い方をする人は「止める」で会員証を出せなくできます。',
    'admin.who': '名前 / 識別子',
    'admin.state': '状態',
    'admin.only': '管理者だけが見られるページです。',
    'admin.pending': '確認待ち', 'admin.approved': '利用できる', 'admin.rejected': '止めている',
    'admin.approve': '利用を認める', 'admin.reject': '止める',
  },
  en: {
    'switch.lang': '日本語',
    'nav.home': 'Home', 'nav.verify': 'Verify a VC', 'nav.admin': 'Admin', 'nav.menu': 'Menu', 'nav.close': 'Close',
    'footer.about': 'A practice ID server for trying DID / VC with passkeys, ORCID / GakuNin RDM / email sign-in, and wallet binding.',
    'footer.did': "This server's DID document (public key)",
    'footer.by': 'Run by Satoru Nakamura',
    'theme.auto': 'Theme: auto', 'theme.light': 'Theme: light', 'theme.dark': 'Theme: dark',

    'home.heroTitle': 'LDAS ID — Digital Membership',
    'home.lead': 'Sign in with ORCID, GakuNin RDM, or an email address to issue and manage a verifiable membership credential for connected data spaces and apps.',
    'home.ctaPrimary': 'Sign in to get started',
    'home.ctaVerify': 'Verify a credential',
    'home.stepsTitle': 'How it works (3 steps)',
    'home.step1Title': 'Sign in',
    'home.step1Text': 'Log in with ORCID, GakuNin RDM, or an email verification code. Your raw email address is never stored on the server.',
    'home.step2Title': 'Verify your affiliation (optional)',
    'home.step2Text': 'Confirm your university or organization via institutional email or GakuNin RDM to unlock institutional access.',
    'home.step3Title': 'Use with connected apps',
    'home.step3Text': 'When signing in to a connected app, choose which items (name, affiliation, etc.) to share before approving.',
    'home.techNote': 'For developers & specs (W3C VC / SD-JWT / OID4VP / OpenAPI 3.1)',
    'home.accountTitle': 'Account management',
    'home.accountLead': 'Verify your affiliation, issue or revoke credentials (VC), and manage passkeys.',
    'home.memberActionsTitle': 'Credential (VC) & account settings',
    'home.walletOptionalSummary': 'Link a Web3 wallet (optional — only needed for apps like Clio-X)',
    'home.new': 'New here',
    'home.newText': 'Sign in with ORCID, GakuNin RDM, or an email address (6-digit code; raw address is never stored). You can get a credential right away.',
    'home.orcid': 'Sign in with ORCID',
    'home.returning': 'Already added a passkey',
    'home.passkeyLogin': 'Log in with a passkey',
    'home.wallet': 'Wallet',
    'home.affiliation': 'Verified affiliation',
    'home.affilTitle': 'Verify your institutional / corporate domain',
    'home.affilDesc': 'Verify via a 6-digit code sent to your institutional email, or via GakuNin RDM. Your raw email address is never stored; only the domain and organization name become selectively disclosable.',
    'home.emailPlaceholder': 'e.g. name@example.ac.jp',
    'home.sendCode': 'Send code',
    'home.codePlaceholder': '6-digit code',
    'home.verifyCode': 'Verify code',
    'home.grdmLink': 'Verify via GakuNin RDM',
    'home.verifiedBadge': '✓ Verified',
    'home.reverifyAffil': 'Change / re-verify affiliation',
    'home.methodGrdm': 'GakuNin RDM (GakuNin)',
    'home.methodEmail': 'Email verification code',
    'home.affilVerifiedHeadline': '✓ Verified: {0}{1}',
    'home.affilVerifiedMeta': 'Method: {0} / Verified at: {1}',
    'home.none': '(not linked)',
    'home.admin': 'Admin',
    'home.noteTitle': 'Before you link a wallet',
    'home.note1': '<strong>Use a new wallet made just for this.</strong> Do not use a wallet that holds money or anything valuable. MetaMask lets you create as many accounts as you like, for free.',
    'home.note2': 'Linking records "your name / identifier = this address" on this site, and anyone you show your credential to learns it too. Blockchain records are public, so whatever this address does becomes visible as something you did.',
    'home.note3': 'This site stores the address only. It never receives your private key or balance.',
    'home.note4': 'You will only be asked to sign a short text. No money moves. If you are asked to send funds or approve a transaction, close the window without confirming.',
    'home.link': 'Link a MetaMask wallet',
    'home.relink': 'Link a different wallet',
    'home.issue': 'Issue a credential (VC)',
    'home.revokeSelf': 'Revoke my issued VCs now',
    'home.revokeConfirm': 'This adds your previously issued credentials to the revocation list (/status/1). Continue? (You can issue a fresh credential right away.)',
    'home.addPasskey': 'Add a passkey on this device',
    'home.logout': 'Log out',
    'msg.revokedSelf': 'Revoked previous credentials (index={0}). Your new status index is {1}.',
    'home.vcTitle': 'Your VC (as a JWT)',
    'home.vcText': 'This string is the credential itself. On the <a id="toVerify" href="/verify">verify page</a> you can check it is genuine without asking this ID server.',
    'home.payload': 'Contents',
    'home.didDoc': "This server's DID document (public key)",
    'home.toVerify': 'Verify a VC',
    'home.returnBannerTitle': 'App sign-in request',
    'home.returnBannerText': '{0} is requesting your membership credential (VC). If you trust this site, issue a credential and return.',
    'home.returnApprove': 'Issue VC and return to app',
    'home.returnCancel': 'Cancel',
    'home.returnInvalid': 'Ignored the requested return_to URL because its origin is not allowed.',
    'home.returnLoginHint': 'Sign in with ORCID, GakuNin RDM, email, or a passkey to issue a VC and return to {0}.',

    'login.title': 'Sign in to LDAS ID',
    'login.lead': 'Sign in with ORCID, GakuNin RDM, an email code, or a registered passkey.',
    'login.nextHint': 'After signing in, you will continue to the app authorization screen.',

    'authz.title': 'Share your info with this app?',
    'authz.lead': 'Review what will be shared. You can uncheck optional items to keep them private.',
    'authz.requestText': 'Select the items to share and click "Allow and return".',
    'authz.claimName': 'Name',
    'authz.claimMember': 'Membership',
    'authz.claimAffiliation': 'Affiliation',
    'authz.claimEmailDomain': 'Email domain',
    'authz.claimIssuer': 'Issuer DID',
    'authz.required': 'Required',
    'authz.optional': 'Optional',
    'authz.techSummary': 'Technical details (OID4VP / SD-JWT)',
    'authz.approve': 'Allow and return to app',
    'authz.cancel': 'Cancel',
    'authz.switchAccount': 'Use another account',
    'authz.missingReturn': 'Missing return_to URL. Open this page from the sign-in button of the requesting app.',
    'authz.clientMismatch': 'Stopped: the requesting app (client_id) does not match where the credential would be sent (redirect_uri). Please tell the app\'s administrator.',
    'status.pending': 'Waiting for review.',
    'status.approved': 'You can issue a credential.',
    'status.verified': 'Identity verified. You can issue a credential.',
    'status.rejected': 'Your access has been stopped. Please contact the administrator.',
    'msg.passkeyAdded': 'Passkey added. Next time you can log in with your fingerprint or face.',
    'msg.passkeyFailed': 'Could not add a passkey: {0}',
    'msg.noMetaMask': 'MetaMask was not found',
    'msg.linked': 'Linked wallet {0}. Please issue your credential again.',
    'msg.linkFailed': 'Could not link the wallet: {0}',
    'msg.loggedIn': 'Logged in.',
    'msg.loginFailed': 'Could not log in: {0}',
    'msg.orcidCancelled': 'ORCID sign-in was cancelled.',
    'msg.codeSent': 'Verification code sent (domain: {0} / affiliation: {1}). Enter it within 10 minutes.',
    'msg.affilVerified': 'Affiliation verified: {0} ({1}). Please re-issue your VC if needed.',
    'msg.grdmLinked': 'Affiliation verified via GakuNin RDM.',
    'msg.grdmCancelled': 'GakuNin RDM link was cancelled.',
    'msg.grdmUnconfigured': 'GakuNin RDM OAuth2 is not configured on this server yet.',

    'verify.title': 'Verify a VC',
    'verify.lead': 'Everything here happens <strong>inside your browser</strong>. The ID server\'s database is never asked. Only the public DID document (public key) of the issuer is used. Apps such as Clio-X can check credentials the same way.',
    'verify.placeholder': 'Paste a VC (JWT) starting with eyJ...',
    'verify.go': 'Verify',
    'verify.holderTitle': 'Is the person showing this credential its holder?',
    'verify.holderText': 'Even with a valid signature, the credential string can be copied. This credential is about wallet <code id="holderAddr"></code>. Ask the person to sign a one-time text with that wallet, and check that the signer is the same wallet (done entirely in your browser).',
    'verify.challenge': 'Ask for a MetaMask signature',
    'verify.back': 'Back to LDAS ID',
    'step.header': 'Read the header: algorithm {0}, key {1}',
    'step.mismatch': 'The key owner ({0}) and the issuer ({1}) do not match',
    'step.issuer': 'Issuer: {0}',
    'step.didDoc': 'Fetched the DID document: {0}',
    'step.noKey': 'The DID document does not list this key',
    'step.notAssertion': 'This key is not designated for signing credentials',
    'step.keyFound': 'Found the signing key in the DID document',
    'step.sigOk': 'The signature is valid and not expired. Nothing was altered',
    'step.statusOk': 'Checked revocation list ({0}, index={1}): active (not revoked)',
    'step.statusRevoked': 'Checked revocation list ({0}, index={1}): REVOKED',
    'step.conclusion': 'Conclusion: {0} states that "{1} ({2}) is a member of {3}" (valid until {4})',
    'step.evidence': 'How the issuer checked: {0}',
    'step.unbound': 'This credential is not bound to a wallet. Anyone who has the string can present it',
    'step.failed': 'Could not verify: {0}',
    'holder.ok': 'Signed by {0}. This matches the wallet in the credential: this person is the holder.',
    'holder.ng': 'Signed by {0}. This differs from the wallet in the credential ({1}): not the holder.',
    'holder.failed': 'Could not check: {0}',

    'admin.title': 'People',
    'admin.lead': 'Everyone who signed in with ORCID, GakuNin RDM, or email. Access is granted automatically. Use "Stop" to block someone from getting credentials.',
    'admin.who': 'Name / Identifier',
    'admin.state': 'Status',
    'admin.only': 'Only administrators can see this page.',
    'admin.pending': 'Waiting', 'admin.approved': 'Allowed', 'admin.rejected': 'Stopped',
    'admin.approve': 'Allow', 'admin.reject': 'Stop',
  },
};

const read = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
const write = (k, v) => { try { localStorage.setItem(k, v); } catch {} };

export let lang = read('lang') || (navigator.language.startsWith('ja') ? 'ja' : 'en');

export function t(key, ...args) {
  const s = STRINGS[lang][key] ?? STRINGS.ja[key] ?? key;
  return s.replace(/\{(\d)\}/g, (_, i) => args[i] ?? '');
}

const listeners = [];
export const onLangChange = (fn) => listeners.push(fn);

function apply() {
  document.documentElement.lang = lang;
  for (const el of document.querySelectorAll('[data-i18n]')) el.textContent = t(el.dataset.i18n);
  for (const el of document.querySelectorAll('[data-i18n-html]')) el.innerHTML = t(el.dataset.i18nHtml);
  for (const el of document.querySelectorAll('[data-i18n-placeholder]')) el.placeholder = t(el.dataset.i18nPlaceholder);
  langBtn.textContent = t('switch.lang');
  themeBtn.textContent = t(`theme.${theme}`);
  updateMenuLabel();
  listeners.forEach((fn) => fn());
}

const THEMES = ['auto', 'light', 'dark'];
let theme = read('theme') || 'auto';
const setTheme = () => {
  if (theme === 'auto') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
};

const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids); return e; };
const navLink = (href, key) => {
  const a = el('a', { href }); a.dataset.i18n = key;
  if (location.pathname === href) a.setAttribute('aria-current', 'page');
  return a;
};
const langBtn = el('button', { className: 'secondary small' });
const themeBtn = el('button', { className: 'secondary small' });
langBtn.onclick = () => { lang = lang === 'ja' ? 'en' : 'ja'; write('lang', lang); apply(); };
themeBtn.onclick = () => { theme = THEMES[(THEMES.indexOf(theme) + 1) % 3]; write('theme', theme); setTheme(); apply(); };

export const adminNav = navLink('/admin', 'nav.admin');
adminNav.hidden = location.pathname !== '/admin';

const menuBtn = el('button', { type: 'button', className: 'menu-toggle' });
menuBtn.setAttribute('aria-expanded', 'false');
menuBtn.setAttribute('aria-controls', 'site-nav-panel');
const navPanel = el('div', { id: 'site-nav-panel', className: 'nav-panel' },
  el('nav', {}, navLink('/', 'nav.home'), navLink('/verify', 'nav.verify'), adminNav),
  el('div', { className: 'switches' }, langBtn, themeBtn));
const siteHeader = el('header', { className: 'site' },
  el('div', { className: 'inner' },
    el('a', { href: '/', className: 'brand', textContent: 'LDAS ID' }),
    menuBtn,
    navPanel));

function updateMenuLabel() {
  const open = siteHeader.classList.contains('is-open');
  menuBtn.textContent = open ? `✕ ${t('nav.close')}` : `☰ ${t('nav.menu')}`;
  menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
}
function closeMenu() {
  if (!siteHeader.classList.contains('is-open')) return;
  siteHeader.classList.remove('is-open');
  updateMenuLabel();
}
menuBtn.onclick = () => {
  siteHeader.classList.toggle('is-open');
  updateMenuLabel();
};
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeMenu(); });
document.addEventListener('click', (e) => { if (!siteHeader.contains(e.target)) closeMenu(); });

document.body.prepend(siteHeader);

const about = el('p'); about.dataset.i18n = 'footer.about';
const did = el('a', { href: '/.well-known/did.json' }); did.dataset.i18n = 'footer.did';
const apiDocs = el('a', { href: '/docs', textContent: 'API Docs (OpenAPI)' });
const by = el('span'); by.dataset.i18n = 'footer.by';
document.body.append(el('footer', { className: 'site' },
  el('div', { className: 'inner' }, about, el('p', {}, did, ' · ', apiDocs, ' · ', by))));

setTheme();
apply();
