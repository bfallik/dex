package server

import (
	"html/template"
	"net/http"
	"net/url"

	"github.com/coreos/dex/pkg/log"
	"github.com/coreos/dex/user"
	"github.com/coreos/go-oidc/key"
)

type invitationTemplateData struct {
	Error, Message string
}

type InvitationHandler struct {
	tpl       *template.Template
	issuerURL url.URL
	um        *user.Manager
	keysFunc  func() ([]key.PublicKey, error)
}

func (h *InvitationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		h.handleGET(w, r)
	case "POST":
		h.handlePOST(w, r)
	default:
		writeAPIError(w, http.StatusMethodNotAllowed, newAPIError(errorInvalidRequest,
			"method not allowed"))
	}
}

func (h *InvitationHandler) handleGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	token := q.Get("token")

	keys, err := h.keysFunc()
	if err != nil {
		log.Errorf("internal error getting public keys: %v", err)
		execTemplateWithStatus(w, h.tpl, resetPasswordTemplateData{
			Error:        "There's been an error processing your request.",
			Message:      "Please try again later.",
			DontShowForm: true,
		}, http.StatusInternalServerError)
		return
	}

	invite, err := user.ParseAndVerifyInvitationToken(token, h.issuerURL, keys)
	if err != nil {
		log.Debugf("invalid invitation token: %v", err)
		execTemplateWithStatus(w, h.tpl, resetPasswordTemplateData{
			Error:        "Bad Invitation Token",
			Message:      "Your invitation could not be verified",
			DontShowForm: true,
		}, http.StatusBadRequest)
		return
	}

	_, err = h.um.VerifyEmail(invite)
	if err != nil && err != user.ErrorEmailAlreadyVerified {
		// Allow AlreadyVerified folks to pass through- otherwise
		// folks who encounter an error after passing this point will
		// never be able to set their passwords.
		log.Debugf("error attempting to verify email: %v", err)
		switch err {
		case user.ErrorEVEmailDoesntMatch:
			execTemplateWithStatus(w, h.tpl, resetPasswordTemplateData{
				Error:        "Invalid Invitation Link",
				Message:      "Your email does not match the email address on file.",
				DontShowForm: true,
			}, http.StatusBadRequest)
			return
		case user.ErrorPasswordAlreadyChanged:
			// TODO joeatwork - there is currently no way to request a new invitation link.
			execTemplateWithStatus(w, h.tpl, resetPasswordTemplateData{
				Error:        "Link Expired",
				Message:      "Your invitation link is no longer valid. Please request a new one",
				DontShowForm: true,
			}, http.StatusBadRequest)
			return
		default:
			log.Errorf("internal error verifying email: %v", err)
			execTemplateWithStatus(w, h.tpl, resetPasswordTemplateData{
				Error:        "Error Processing Request",
				Message:      "Please try again later.",
				DontShowForm: true,
			}, http.StatusInternalServerError)
			return
		}
	}

	execTemplate(w, h.tpl, resetPasswordTemplateData{
		Token: token,
	})
}

func (h *InvitationHandler) handlePOST(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	plaintext := r.FormValue("password")

	keys, err := h.keysFunc()
	if err != nil {
		log.Errorf("error getting public keys: %v", err)
		execTemplateWithStatus(w, h.tpl, resetPasswordTemplateData{
			Error:        "There's been an error processing your request.",
			Message:      "Please try again later.",
			DontShowForm: true,
		}, http.StatusInternalServerError)
		return
	}

	invite, err := user.ParseAndVerifyInvitationToken(token, h.issuerURL, keys)
	if err != nil {
		log.Debugf("invalid invitation token: %v", err)
		execTemplateWithStatus(w, h.tpl, resetPasswordTemplateData{
			Error:        "Bad Invitation Token",
			Message:      "Your invitation could not be verified",
			DontShowForm: true,
		}, http.StatusBadRequest)
		return
	}

	cbURL, err := h.um.ChangePassword(invite, plaintext)
	if err != nil {
		log.Debugf("error attempting to change password: %v", err)
		switch err {
		case user.ErrorPasswordAlreadyChanged:
			execTemplateWithStatus(w, h.tpl, resetPasswordTemplateData{
				Error:        "Link Expired",
				Message:      "The invitation is no longer valid. If you need to change your password, generate a new password change email.",
				DontShowForm: true,
			}, http.StatusBadRequest)
		case user.ErrorInvalidPassword:
			execTemplateWithStatus(w, h.tpl, resetPasswordTemplateData{
				Error:   "Invalid Password",
				Message: "Please choose a password which is at least six characters.",
				Token:   token,
			}, http.StatusBadRequest)
		default:
			log.Errorf("internal error changing password: %v", err)
			execTemplateWithStatus(w, h.tpl, resetPasswordTemplateData{
				Error:        "Error Processing Request",
				Message:      "Please try again later",
				DontShowForm: true,
			}, http.StatusInternalServerError)
		}

		return
	}

	if cbURL == nil {
		execTemplate(w, h.tpl, resetPasswordTemplateData{
			Success: true,
		})
	} else {
		http.Redirect(w, r, cbURL.String(), http.StatusSeeOther)
	}
}
