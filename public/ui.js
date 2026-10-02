// Shared page chrome: header (site name, navigation, language and theme switches) and footer.
// Markup uses data-i18n="key" (text) or data-i18n-html="key" (trusted markup from this file only).

const STRINGS = {
  ja: {
    'switch.lang': 'English',
    'nav.home': 'ホーム', 'nav.verify': 'VC を検証', 'nav.admin': '管理',
    'footer.about': '練習用の ID サーバです。DID / VC とパスキー、ORCID、ウォレットの結びつけを試すために作りました。',
    'footer.did': 'このサーバの DID 文書（公開鍵）',
    'footer.by': '運営: 中村 覚（東京大学）',
    'theme.auto': '表示: 自動', 'theme.light': '表示: ライト', 'theme.dark': '表示: ダーク',

    'home.lead': 'ORCID でサインインした人に、会員証（検証可能な証明書 = VC）を出す練習用のサーバです。ウォレットを結びつけると、会員証はそのウォレットの持ち主だけが使えるものになります。',
    'home.new': 'はじめての方',
    'home.newText': 'ORCID でサインインしてください。ORCID iD があれば、そのまま会員証を受け取れます。',
    'home.orcid': 'ORCID でサインイン',
    'home.returning': 'パスキーを登録済みの方',
    'home.passkeyLogin': 'パスキーでログイン',
    'home.wallet': 'ウォレット',
    'home.none': '（未登録）',
    'home.admin': '管理画面',
    'home.noteTitle': 'ウォレットを結びつける前に',
    'home.note1': '<strong>このためだけの新しいウォレットを使ってください。</strong>お金や大事な資産の入ったウォレットは使わないでください。MetaMask ではアカウントを無料で何個でも作れます。',
    'home.note2': '結びつけると、「あなたの ORCID の氏名 = このアドレス」という対応がこのサイトに記録されます。会員証を見せた相手にも伝わります。チェーン上の記録は誰でも見られるので、このアドレスでの行動は、あなたの名前と結びついて見えるようになります。',
    'home.note3': 'このサイトが保存するのはアドレスだけです。秘密の鍵や残高は受け取りません。',
    'home.note4': '求めるのは、短い文への署名だけです。お金は動きません。もし送金や「取引の承認」を求める画面が出たら、押さずに閉じてください。',
    'home.link': 'MetaMask のウォレットを結びつける',
    'home.relink': '別のウォレットに付け替える',
    'home.issue': '会員証（VC）を発行する',
    'home.addPasskey': 'この端末にパスキーを追加',
    'home.logout': 'ログアウト',
    'home.vcTitle': '発行された VC（JWT 形式）',
    'home.vcText': 'この文字列が「証明書」本体です。<a id="toVerify" href="/verify">検証ページ</a>で、この ID サーバに問い合わせずに本物か確かめられます。',
    'home.payload': '中身',
    'home.didDoc': 'このサーバの DID 文書（公開鍵）',
    'home.toVerify': 'VC を検証する',
    'status.pending': '確認待ちです。',
    'status.approved': '会員証を発行できます。',
    'status.rejected': '利用が止められています。管理者にお問い合わせください。',
    'msg.passkeyAdded': 'パスキーを追加しました。次からは指紋・顔認証でログインできます。',
    'msg.passkeyFailed': '追加できませんでした: {0}',
    'msg.noMetaMask': 'MetaMask が見つかりません',
    'msg.linked': 'ウォレット {0} を結びつけました。会員証を発行し直してください。',
    'msg.linkFailed': '結びつけられませんでした: {0}',
    'msg.loggedIn': 'ログインしました。',
    'msg.loginFailed': 'ログインできませんでした: {0}',
    'msg.orcidCancelled': 'ORCID でのサインインが取り消されました。',

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
    'step.conclusion': '結論: {0} が「{1}（{2}）は {3} の会員」と証明しています（{4} まで有効）',
    'step.evidence': '発行者がどう確かめたか: {0}',
    'step.unbound': 'この会員証はウォレットに結びついていません。文字列を持っている人なら誰でも出せます',
    'step.failed': '検証できませんでした: {0}',
    'holder.ok': '署名したのは {0}。会員証のウォレットと一致します。この人が持ち主です。',
    'holder.ng': '署名したのは {0}。会員証のウォレット（{1}）と違います。持ち主ではありません。',
    'holder.failed': '確かめられませんでした: {0}',

    'admin.title': '利用者',
    'admin.lead': 'ORCID でサインインした人の一覧です。ORCID iD があれば自動で使えるようになります。おかしな使い方をする人は「止める」で会員証を出せなくできます。',
    'admin.who': '名前 / ORCID iD',
    'admin.state': '状態',
    'admin.only': '管理者だけが見られるページです。',
    'admin.pending': '確認待ち', 'admin.approved': '利用できる', 'admin.rejected': '止めている',
    'admin.approve': '利用を認める', 'admin.reject': '止める',
  },
  en: {
    'switch.lang': '日本語',
    'nav.home': 'Home', 'nav.verify': 'Verify a VC', 'nav.admin': 'Admin',
    'footer.about': 'A practice ID server for trying DID / VC with passkeys, ORCID sign-in and wallet binding.',
    'footer.did': "This server's DID document (public key)",
    'footer.by': 'Run by Satoru Nakamura (The University of Tokyo)',
    'theme.auto': 'Theme: auto', 'theme.light': 'Theme: light', 'theme.dark': 'Theme: dark',

    'home.lead': 'A practice server that gives a membership credential (a Verifiable Credential, VC) to anyone who signs in with ORCID. Link a wallet, and the credential can only be used by whoever holds that wallet.',
    'home.new': 'New here',
    'home.newText': 'Sign in with ORCID. If you have an ORCID iD, you can get a credential right away.',
    'home.orcid': 'Sign in with ORCID',
    'home.returning': 'Already added a passkey',
    'home.passkeyLogin': 'Log in with a passkey',
    'home.wallet': 'Wallet',
    'home.none': '(not linked)',
    'home.admin': 'Admin',
    'home.noteTitle': 'Before you link a wallet',
    'home.note1': '<strong>Use a new wallet made just for this.</strong> Do not use a wallet that holds money or anything valuable. MetaMask lets you create as many accounts as you like, for free.',
    'home.note2': 'Linking records "your ORCID name = this address" on this site, and anyone you show your credential to learns it too. Blockchain records are public, so whatever this address does becomes visible as something you did.',
    'home.note3': 'This site stores the address only. It never receives your private key or balance.',
    'home.note4': 'You will only be asked to sign a short text. No money moves. If you are asked to send funds or approve a transaction, close the window without confirming.',
    'home.link': 'Link a MetaMask wallet',
    'home.relink': 'Link a different wallet',
    'home.issue': 'Issue a credential (VC)',
    'home.addPasskey': 'Add a passkey on this device',
    'home.logout': 'Log out',
    'home.vcTitle': 'Your VC (as a JWT)',
    'home.vcText': 'This string is the credential itself. On the <a id="toVerify" href="/verify">verify page</a> you can check it is genuine without asking this ID server.',
    'home.payload': 'Contents',
    'home.didDoc': "This server's DID document (public key)",
    'home.toVerify': 'Verify a VC',
    'status.pending': 'Waiting for review.',
    'status.approved': 'You can issue a credential.',
    'status.rejected': 'Your access has been stopped. Please contact the administrator.',
    'msg.passkeyAdded': 'Passkey added. Next time you can log in with your fingerprint or face.',
    'msg.passkeyFailed': 'Could not add a passkey: {0}',
    'msg.noMetaMask': 'MetaMask was not found',
    'msg.linked': 'Linked wallet {0}. Please issue your credential again.',
    'msg.linkFailed': 'Could not link the wallet: {0}',
    'msg.loggedIn': 'Logged in.',
    'msg.loginFailed': 'Could not log in: {0}',
    'msg.orcidCancelled': 'ORCID sign-in was cancelled.',

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
    'step.conclusion': 'Conclusion: {0} states that "{1} ({2}) is a member of {3}" (valid until {4})',
    'step.evidence': 'How the issuer checked: {0}',
    'step.unbound': 'This credential is not bound to a wallet. Anyone who has the string can present it',
    'step.failed': 'Could not verify: {0}',
    'holder.ok': 'Signed by {0}. This matches the wallet in the credential: this person is the holder.',
    'holder.ng': 'Signed by {0}. This differs from the wallet in the credential ({1}): not the holder.',
    'holder.failed': 'Could not check: {0}',

    'admin.title': 'People',
    'admin.lead': 'Everyone who signed in with ORCID. Having an ORCID iD is enough to get access. Use "Stop" to block someone from getting credentials.',
    'admin.who': 'Name / ORCID iD',
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
document.body.prepend(el('header', { className: 'site' },
  el('div', { className: 'inner' },
    el('a', { href: '/', className: 'brand', textContent: 'LDAS ID' }),
    el('nav', {}, navLink('/', 'nav.home'), navLink('/verify', 'nav.verify'), adminNav),
    el('div', { className: 'switches' }, langBtn, themeBtn))));

const about = el('p'); about.dataset.i18n = 'footer.about';
const did = el('a', { href: '/.well-known/did.json' }); did.dataset.i18n = 'footer.did';
const by = el('span'); by.dataset.i18n = 'footer.by';
document.body.append(el('footer', { className: 'site' },
  el('div', { className: 'inner' }, about, el('p', {}, did, ' · ', by))));

setTheme();
apply();
