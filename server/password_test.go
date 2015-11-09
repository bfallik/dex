package server

import (
	"bytes"
	"fmt"
	htmltemplate "html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/key"
	"github.com/kylelemons/godebug/pretty"

	"github.com/coreos/dex/email"
	"github.com/coreos/dex/pkg/html"
	"github.com/coreos/dex/pkg/log"
	"github.com/coreos/dex/user"
)

var (
	rpwUserID     string
	rpwVerifiedID string
	rpwGoodSigner jose.Signer
	rpwBadSigner  jose.Signer
)

func init() {
	log.EnableDebug()

	rpwUserID = "ID-1"
	rpwVerifiedID = "ID-Verified"
	rpwGoodSigner = key.NewPrivateKeySet([]*key.PrivateKey{testPrivKey},
		time.Now().Add(time.Minute)).Active().Signer()

	badKey, err := key.GeneratePrivateKey()
	if err != nil {
		panic(fmt.Sprintf("couldn't make new key: %q", err))
	}

	rpwBadSigner = key.NewPrivateKeySet([]*key.PrivateKey{badKey},
		time.Now().Add(time.Minute)).Active().Signer()

}

func TestSendResetPasswordEmailHandler(t *testing.T) {
	str := func(s string) []string {
		return []string{s}
	}

	textTemplateString := `{{define "password-reset.txt"}}{{.link}}{{end}}`
	textTemplates := template.New("text")
	_, err := textTemplates.Parse(textTemplateString)
	if err != nil {
		t.Fatalf("error parsing text templates: %v", err)
	}

	htmlTemplates := htmltemplate.New("html")

	tests := []struct {
		query url.Values

		method string

		wantFormValues  *url.Values
		wantCode        int
		wantRedirectURL *url.URL
		wantEmailer     *testEmailer
		wantPRRedirect  *url.URL
		wantPRUserID    string
		wantPRPassword  string
	}{
		// First we'll test all the requests for happy path #1:
		{ // Case 0

			// STEP 1.1 - User clicks on link from local-login page and has a
			// session_key, which will prompt a redirect to page which has
			// instead a client_id and redirect_uri.
			query: url.Values{
				"session_key": str("code-2"),
			},
			method: "GET",

			wantCode: http.StatusSeeOther,
			wantRedirectURL: &url.URL{
				Scheme: testIssuerURL.Scheme,
				Host:   testIssuerURL.Host,
				Path:   httpPathSendResetPassword,
				RawQuery: url.Values{
					"client_id":    str(testClientID),
					"redirect_uri": str(testRedirectURL.String()),
				}.Encode(),
			},
		},
		{ // Case 1

			// STEP 1.2 - This is the request that happens as a result of the
			// redirect. The client_id and redirect_uri should be in the form on
			// the page.
			query: url.Values{
				"client_id":    str(testClientID),
				"redirect_uri": str(testRedirectURL.String()),
			},
			method: "GET",

			wantCode: http.StatusOK,
			wantFormValues: &url.Values{
				"client_id":    str(testClientID),
				"redirect_uri": str(testRedirectURL.String()),
				"email":        str(""),
			},
		},
		{ // Case 2
			// STEP 1.3 - User enters a valid email, gets success page.  The
			// values from the GET redirect are resent in the form POST along
			// with the email.
			query: url.Values{
				"client_id":    str(testClientID),
				"redirect_uri": str(testRedirectURL.String()),
				"email":        str("Email-1@example.com"),
			},
			method: "POST",

			wantCode: http.StatusOK,
			wantEmailer: &testEmailer{
				to:      str("Email-1@example.com"),
				from:    "noreply@example.com",
				subject: "Reset Your Password",
			},
			wantPRUserID:   "ID-1",
			wantPRRedirect: &testRedirectURL,
			wantPRPassword: "password",
		},

		// Happy Path #2 - no email or redirect
		{ // Case 3

			// STEP 2.1 - user somehow ends up on reset page with nothing but a client id
			query: url.Values{
				"client_id": str(testClientID),
			},
			method: "GET",

			wantCode: http.StatusOK,
			wantFormValues: &url.Values{
				"client_id":    str(testClientID),
				"redirect_uri": str(""),
				"email":        str(""),
			},
		},
		{ // Case 4

			// STEP 2.3 - There is no STEP 2 because we don't have the redirect.
			query: url.Values{
				"email":     str("Email-1@example.com"),
				"client_id": str(testClientID),
			},
			method: "POST",

			wantCode: http.StatusOK,
			wantEmailer: &testEmailer{
				to:      str("Email-1@example.com"),
				from:    "noreply@example.com",
				subject: "Reset Your Password",
			},
			wantPRPassword: "password",
			wantPRUserID:   "ID-1",
		},

		// Some error conditions:
		{ // Case 5
			// STEP 1.3.1 - User enters an invalid email, gets form again.
			query: url.Values{
				"client_id":    str(testClientID),
				"redirect_uri": str(testRedirectURL.String()),
				"email":        str("NOT EMAIL"),
			},
			method: "POST",

			wantCode: http.StatusBadRequest,
			wantFormValues: &url.Values{
				"client_id":    str(testClientID),
				"redirect_uri": str(testRedirectURL.String()),
				"email":        str(""),
			},
		},
		{ // Case 6
			// STEP 1.3.2 - User enters a valid email but for a user not in the
			// system. They still get the success page, but no email is sent.
			query: url.Values{
				"client_id":    str(testClientID),
				"redirect_uri": str(testRedirectURL.String()),
				"email":        str("NOSUCHUSER@example.com"),
			},
			method: "POST",

			wantCode: http.StatusOK,
		},
		{ // Case 7

			// STEP 1.1.1 - User clicks on link from local-login page and has a
			// session_key, but it is not-recognized.
			query: url.Values{
				"session_key": str("code-UNKNOWN"),
			},
			method: "GET",

			wantCode: http.StatusBadRequest,
		},
		{ // Case 8

			// STEP 1.2.1 - Someone trying to replace a valid redirect_url with
			// an invalid one.
			query: url.Values{
				"client_id":    str(testClientID),
				"redirect_uri": str("http://evilhackers.example.com"),
			},
			method: "GET",

			wantCode: http.StatusBadRequest,
		},
		{ // Case 9
			// STEP 1.3.4 - User enters a valid email for a user in the system,
			// but with an invalid redirect_uri.
			query: url.Values{
				"client_id":    str(testClientID),
				"redirect_uri": str("http://evilhackers.example.com"),
				"email":        str("Email-1@example.com"),
			},
			method: "POST",

			wantCode: http.StatusBadRequest,
		},
		{ // Case 10

			// User hits the page with a valid email but no client id
			query: url.Values{
				"email": str("Email-1@example.com"),
			},
			method: "GET",

			wantCode: http.StatusBadRequest,
		},
		{ // Case 10

			// Don't send an email without a client id
			query: url.Values{
				"email": str("Email-1@example.com"),
			},
			method: "POST",

			wantCode: http.StatusBadRequest,
		},
		{ // Case 11

			// Empty requests lack a client id
			query:  url.Values{},
			method: "GET",

			wantCode: http.StatusBadRequest,
		},
		{ // Case 12

			// Empty requests lack a client id
			query:  url.Values{},
			method: "POST",

			wantCode: http.StatusBadRequest,
		},
	}

	for i, tt := range tests {
		t.Logf("CASE: %d", i)
		f, err := makeTestFixtures()
		if err != nil {
			t.Fatalf("case %d: could not make test fixtures: %v", i, err)
		}

		_, err = f.srv.NewSession("local", "XXX", "", f.redirectURL, "", true, []string{"openid"})
		if err != nil {
			t.Fatalf("case %d: could not create new session: %v", i, err)
		}

		emailer := &testEmailer{
			sent: make(chan struct{}),
		}
		templatizer := email.NewTemplatizedEmailerFromTemplates(textTemplates, htmlTemplates, emailer)
		f.srv.UserEmailer.SetEmailer(templatizer)
		hdlr := SendResetPasswordEmailHandler{
			tpl:     f.srv.SendResetPasswordEmailTemplate,
			emailer: f.srv.UserEmailer,
			sm:      f.sessionManager,
			cr:      f.clientIdentityRepo,
		}

		w := httptest.NewRecorder()

		var req *http.Request
		u := testIssuerURL
		u.Path = httpPathSendResetPassword
		if tt.method == "POST" {
			req, err = http.NewRequest(tt.method, u.String(), strings.NewReader(tt.query.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			u.RawQuery = tt.query.Encode()
			req, err = http.NewRequest(tt.method, u.String(), nil)
		}
		if err != nil {
			t.Errorf("case %d: unable to form HTTP request: %v", i, err)
		}

		hdlr.ServeHTTP(w, req)
		if tt.wantCode != w.Code {
			t.Errorf("case %d: wantCode=%v, got=%v", i, tt.wantCode, w.Code)
			t.Logf("case %d: Body: %v ", i, w.Body)
			continue
		}

		values, err := html.FormValues("#sendResetPasswordForm", w.Body)
		if err != nil {
			t.Errorf("case %d: could not parse form: %v", i, err)
		}

		if tt.wantFormValues != nil {
			if diff := pretty.Compare(*tt.wantFormValues, values); diff != "" {
				t.Errorf("case %d: Compare(wantFormValues, got) = %v", i, diff)
			}
		}

		if tt.wantRedirectURL != nil {
			location, err := url.Parse(w.Header().Get("location"))
			if err != nil {
				t.Errorf("case %d: could not parse Location header: %v", i, err)
			}
			if diff := pretty.Compare(*tt.wantRedirectURL, *location); diff != "" {
				t.Errorf("case %d: Compare(wantRedirectURL, got) = %v", i, diff)
			}
		}
		if tt.wantEmailer != nil {
			<-emailer.sent
			txt := emailer.text
			emailer.text = ""
			if diff := pretty.Compare(*tt.wantEmailer, *emailer); diff != "" {
				t.Errorf("case %d: Compare(wantEmailer, got) = %v", i, diff)
			}

			u, err := url.Parse(txt)
			if err != nil {
				t.Errorf("case %d: could not parse generated link: %v", i, err)
			}
			token := u.Query().Get("token")
			pubKeys, err := f.srv.KeyManager.PublicKeys()
			if err != nil {
				t.Errorf("case %d: could not parse generated link: %v", i, err)
			}

			pr, err := user.ParseAndVerifyPasswordResetToken(token, testIssuerURL, pubKeys)
			if err != nil {
				t.Errorf("case %d: could not parse reset token: %v", i, err)
			}

			if tt.wantPRPassword != string(pr.Password()) {
				t.Errorf("case %d: wantPRPassword=%v, got=%v", i, tt.wantPRPassword, string(pr.Password()))
			}

			if tt.wantPRRedirect == nil {
				if pr.Callback() != nil {
					t.Errorf("case %d: wantPRCallback=nil, got=%v", i, pr.Callback())

				}
			} else {
				if *tt.wantPRRedirect != *pr.Callback() {
					t.Errorf("case %d: wantPRCallback=%v, got=%v", i, tt.wantPRRedirect, pr.Callback())
				}
			}

		}
	}
}

type resetPasswordTestCase struct {
	userID string
	query  url.Values

	method   string
	path     string
	verified bool

	wantFormValues *url.Values
	wantCode       int
	wantPassword   string
}

func strToSlice(s string) []string {
	return []string{s}
}

func TestResetPasswordHandler(t *testing.T) {
	makePRToken := func(password, clientID string, callback url.URL, expires time.Duration, signer jose.Signer) string {
		pr := user.NewPasswordReset(user.User{ID: rpwUserID},
			user.Password(password),
			testIssuerURL,
			clientID,
			callback,
			expires)

		jwt, err := jose.NewSignedJWT(pr.Claims, signer)
		if err != nil {
			t.Fatalf("couldn't make token: %q", err)
		}
		token := jwt.Encode()
		return token
	}

	tests := []resetPasswordTestCase{
		// Scenario 1: Happy Path
		resetPasswordTestCase{ // Case 0
			// Step 1.1 - User clicks link in email, has valid token.
			userID: rpwUserID,
			query: url.Values{
				"token": strToSlice(makePRToken("password", testClientID, testRedirectURL, time.Hour*1, rpwGoodSigner)),
			},
			method:   "GET",
			path:     httpPathResetPassword,
			verified: false,

			wantCode: http.StatusOK,
			wantFormValues: &url.Values{
				"password": strToSlice(""),
				"token":    strToSlice(makePRToken("password", testClientID, testRedirectURL, time.Hour*1, rpwGoodSigner)),
			},
			wantPassword: "password",
		},
		resetPasswordTestCase{ // Case 1
			// Step 1.2 - User enters in new valid password, password is changed, user is redirected.
			userID: rpwUserID,
			query: url.Values{
				"token":    strToSlice(makePRToken("password", testClientID, testRedirectURL, time.Hour*1, rpwGoodSigner)),
				"password": strToSlice("new_password"),
			},
			method:   "POST",
			path:     httpPathResetPassword,
			verified: false,

			wantCode:       http.StatusSeeOther,
			wantFormValues: &url.Values{},
			wantPassword:   "NEW_PASSWORD",
		},
		// Scenario 2: Happy Path, but without redirect.
		resetPasswordTestCase{ // Case 2
			// Step 2.1 - User clicks link in email, has valid token.
			userID: rpwUserID,
			query: url.Values{
				"token": strToSlice(makePRToken("password", testClientID, url.URL{}, time.Hour*1, rpwGoodSigner)),
			},
			method:   "GET",
			path:     httpPathResetPassword,
			verified: false,

			wantCode: http.StatusOK,
			wantFormValues: &url.Values{
				"password": strToSlice(""),
				"token":    strToSlice(makePRToken("password", testClientID, url.URL{}, time.Hour*1, rpwGoodSigner)),
			},
			wantPassword: "password",
		},
		resetPasswordTestCase{ // Case 3
			// Step 2.2 - User enters in new valid password, password is changed, user is redirected.
			userID: rpwUserID,
			query: url.Values{
				"token":    strToSlice(makePRToken("password", testClientID, url.URL{}, time.Hour*1, rpwGoodSigner)),
				"password": strToSlice("new_password"),
			},
			method:   "POST",
			path:     httpPathResetPassword,
			verified: false,

			// no redirect
			wantCode:       http.StatusOK,
			wantFormValues: &url.Values{},
			wantPassword:   "NEW_PASSWORD",
		},
		// Errors
		resetPasswordTestCase{ // Case 4
			// Step 1.1.1 - User clicks link in email, has invalid token.
			userID: rpwUserID,
			query: url.Values{
				"token": strToSlice(makePRToken("password", testClientID, testRedirectURL, time.Hour*1, rpwBadSigner)),
			},
			method:   "GET",
			path:     httpPathResetPassword,
			verified: false,

			wantCode:       http.StatusBadRequest,
			wantFormValues: &url.Values{},
			wantPassword:   "password",
		},
		resetPasswordTestCase{ // Case 5
			// Step 2.2.1 - User enters in new valid password, password is changed, no redirect
			userID: rpwUserID,
			query: url.Values{
				"token":    strToSlice(makePRToken("password", testClientID, url.URL{}, time.Hour*1, rpwGoodSigner)),
				"password": strToSlice("shrt"),
			},
			method:   "POST",
			path:     httpPathResetPassword,
			verified: false,

			// no redirect
			wantCode: http.StatusBadRequest,
			wantFormValues: &url.Values{
				"password": strToSlice(""),
				"token":    strToSlice(makePRToken("password", testClientID, url.URL{}, time.Hour*1, rpwGoodSigner)),
			},
			wantPassword: "password",
		},
		resetPasswordTestCase{ // Case 6
			// Step 2.2.2 - User enters in new valid password, with suspicious token.
			userID: rpwUserID,
			query: url.Values{
				"token":    strToSlice(makePRToken("password", testClientID, url.URL{}, time.Hour*1, rpwBadSigner)),
				"password": strToSlice("shrt"),
			},
			method:   "POST",
			path:     httpPathResetPassword,
			verified: false,

			// no redirect
			wantCode:       http.StatusBadRequest,
			wantFormValues: &url.Values{},
			wantPassword:   "password",
		},
		resetPasswordTestCase{ // Case 7
			// Token lacking client id
			userID: rpwUserID,
			query: url.Values{
				"token":    strToSlice(makePRToken("password", "", url.URL{}, time.Hour*1, rpwGoodSigner)),
				"password": strToSlice("shrt"),
			},
			method:   "GET",
			path:     httpPathResetPassword,
			verified: false,

			wantCode:     http.StatusBadRequest,
			wantPassword: "password",
		},
		resetPasswordTestCase{ // Case 8
			// Token lacking client id
			userID: rpwUserID,
			query: url.Values{
				"token":    strToSlice(makePRToken("password", "", url.URL{}, time.Hour*1, rpwGoodSigner)),
				"password": strToSlice("shrt"),
			},
			method:   "POST",
			path:     httpPathResetPassword,
			verified: false,

			wantCode:     http.StatusBadRequest,
			wantPassword: "password",
		},
	}

	makeHandler := func(f *testFixtures) http.Handler {
		return &ResetPasswordHandler{
			tpl:       f.srv.ResetPasswordTemplate,
			issuerURL: testIssuerURL,
			um:        f.srv.UserManager,
			keysFunc:  f.srv.KeyManager.PublicKeys,
		}
	}

	runPasswordHandler(t, makeHandler, tests)
}

func TestInvitationHandler(t *testing.T) {
	makeInvitationToken := func(password, userID, clientID, email string, callback url.URL, expires time.Duration, signer jose.Signer) string {
		iv := user.NewInvitation(
			user.User{ID: userID, Email: email},
			user.Password(password),
			testIssuerURL,
			clientID,
			callback,
			expires)

		jwt, err := jose.NewSignedJWT(iv.Claims, signer)
		if err != nil {
			t.Fatalf("couldn't make token: %q", err)
		}
		token := jwt.Encode()
		return token
	}

	tests := []resetPasswordTestCase{
		// Happy GET - user clicks a link in an email with a valid token
		resetPasswordTestCase{ // Case 0
			userID: rpwUserID,
			query: url.Values{
				"token": strToSlice(makeInvitationToken("password", rpwUserID, testClientID, "Email-1@example.com", testRedirectURL, time.Hour*1, rpwGoodSigner)),
			},
			method:   "GET",
			path:     httpPathAcceptInvitation,
			verified: true,

			wantCode: http.StatusOK,
			wantFormValues: &url.Values{
				"password": strToSlice(""),
				"token":    strToSlice(makeInvitationToken("password", rpwUserID, testClientID, "Email-1@example.com", testRedirectURL, time.Hour*1, rpwGoodSigner)),
			},
			wantPassword: "password",
		},
		// OK - user email already verified
		resetPasswordTestCase{ // Case 1
			userID: rpwVerifiedID,
			query: url.Values{
				"token": strToSlice(makeInvitationToken("password", rpwVerifiedID, testClientID, "Email-Verified@example.com", testRedirectURL, time.Hour*1, rpwGoodSigner)),
			},
			method:   "GET",
			path:     httpPathAcceptInvitation,
			verified: true,

			wantCode: http.StatusOK,
			wantFormValues: &url.Values{
				"password": strToSlice(""),
				"token":    strToSlice(makeInvitationToken("password", rpwVerifiedID, testClientID, "Email-Verified@example.com", testRedirectURL, time.Hour*1, rpwGoodSigner)),
			},
			wantPassword: "password",
		},
		// Bad token, no email
		resetPasswordTestCase{ // Case 2
			userID: rpwUserID,
			query: url.Values{
				"token": strToSlice(makeInvitationToken("password", rpwUserID, testClientID, "", testRedirectURL, time.Hour*1, rpwGoodSigner)),
			},
			method:   "GET",
			path:     httpPathAcceptInvitation,
			verified: false,

			wantCode:     http.StatusBadRequest,
			wantPassword: "password",
		},
		// Bad token, strange email
		resetPasswordTestCase{ // Case 3
			userID: rpwUserID,
			query: url.Values{
				"token": strToSlice(makeInvitationToken("password", rpwUserID, testClientID, "NOPE@NOPE.com", testRedirectURL, time.Hour*1, rpwGoodSigner)),
			},
			method:   "GET",
			path:     httpPathAcceptInvitation,
			verified: false,

			wantCode:     http.StatusBadRequest,
			wantPassword: "password",
		},
		// Happy path through POST
		resetPasswordTestCase{ // Case 4
			userID: rpwUserID,
			query: url.Values{
				"token":    strToSlice(makeInvitationToken("password", rpwUserID, testClientID, "Doesnt Matter", testRedirectURL, time.Hour*1, rpwGoodSigner)),
				"password": strToSlice("oh dang"),
			},
			method:   "POST",
			path:     httpPathAcceptInvitation,
			verified: false,

			wantCode:       http.StatusSeeOther,
			wantFormValues: &url.Values{},
			wantPassword:   "OH DANG",
		},
		// POST with bad token
		resetPasswordTestCase{ // Case 5
			userID: rpwUserID,
			query: url.Values{
				"token":    strToSlice(makeInvitationToken("password?", rpwUserID, testClientID, "Doesnt Matter", testRedirectURL, time.Hour*1, rpwGoodSigner)),
				"password": strToSlice("oh dang"),
			},
			method:   "POST",
			path:     httpPathAcceptInvitation,
			verified: false,

			wantCode:       http.StatusBadRequest,
			wantFormValues: &url.Values{},
			wantPassword:   "password",
		},
	}

	makeHandler := func(f *testFixtures) http.Handler {
		return &InvitationHandler{
			tpl:       f.srv.ResetPasswordTemplate,
			issuerURL: testIssuerURL,
			um:        f.srv.UserManager,
			keysFunc:  f.srv.KeyManager.PublicKeys,
		}
	}

	runPasswordHandler(t, makeHandler, tests)
}

func runPasswordHandler(t *testing.T, makeHandler func(*testFixtures) http.Handler,
	tests []resetPasswordTestCase) {

	user.PasswordHasher = func(s string) ([]byte, error) {
		return []byte(strings.ToUpper(s)), nil
	}
	defer func() {
		user.PasswordHasher = user.DefaultPasswordHasher
	}()
	for i, tt := range tests {
		f, err := makeTestFixtures()
		if err != nil {
			t.Fatalf("case %d: could not make test fixtures: %v", i, err)
		}

		hdlr := makeHandler(f)

		w := httptest.NewRecorder()
		var req *http.Request
		u := testIssuerURL
		u.Path = tt.path
		if tt.method == "POST" {
			req, err = http.NewRequest(tt.method, u.String(), strings.NewReader(tt.query.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			u.RawQuery = tt.query.Encode()
			req, err = http.NewRequest(tt.method, u.String(), nil)
		}
		if err != nil {
			t.Errorf("case %d: unable to form HTTP request: %v", i, err)
		}

		hdlr.ServeHTTP(w, req)

		if tt.wantCode != w.Code {
			t.Errorf("case %d: wantCode=%v, got=%v", i, tt.wantCode, w.Code)
			t.Logf("case %d: Body: %v ", i, w.Body)
			continue
		}

		values, err := html.FormValues("#resetPasswordForm", bytes.NewReader(w.Body.Bytes()))
		if err != nil {
			t.Errorf("case %d: could not parse form: %v", i, err)
		}

		if tt.wantFormValues != nil {
			if diff := pretty.Compare(*tt.wantFormValues, values); diff != "" {
				t.Errorf("case %d: Compare(wantFormValues, got) = %v", i, diff)
				t.Logf("case %d: Body: %v ", i, w.Body)
			}
		}
		pwi, err := f.srv.PasswordInfoRepo.Get(nil, tt.userID)
		if err != nil {
			t.Errorf("case %d: Error getting Password info: %v", i, err)
		}
		if tt.wantPassword != string(pwi.Password) {
			t.Errorf("case %d: wantPassword=%v, got=%v", i, tt.wantPassword, string(pwi.Password))
		}

		user, err := f.srv.UserManager.Get(tt.userID)
		if err != nil {
			t.Fatalf("case %d: unexpected error: %v", i, err)
		}

		if tt.verified != user.EmailVerified {
			t.Errorf("case %d: want emailVerified: %v got: %v", i, tt.verified, user.EmailVerified)
		}
	}
}

type testEmailer struct {
	from, subject, text, html string
	to                        []string
	sent                      chan struct{}
}

func (t *testEmailer) SendMail(from, subject, text, html string, to ...string) error {
	t.from = from
	t.subject = subject
	t.text = text
	t.html = html
	t.to = to
	t.sent <- struct{}{}

	return nil
}
