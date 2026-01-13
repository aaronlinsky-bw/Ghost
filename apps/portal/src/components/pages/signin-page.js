import React from 'react';
import ActionButton from '../common/action-button';
import CloseButton from '../common/close-button';
// import SiteTitleBackButton from '../common/SiteTitleBackButton';
import AppContext from '../../app-context';
import InputForm from '../common/input-form';
import {ValidateInputForm} from '../../utils/form';
import {hasAvailablePrices, isSigninAllowed, isSignupAllowed} from '../../utils/helpers';
import {ReactComponent as InvitationIcon} from '../../images/icons/invitation.svg';
import {ReactComponent as MicrosoftIcon} from '../../images/icons/microsoft.svg';
import {t} from '../../utils/i18n';

export default class SigninPage extends React.Component {
    static contextType = AppContext;

    constructor(props) {
        super(props);
        this.state = {
            email: '',
            token: undefined,
            azureSsoEnabled: false
        };
    }

    componentDidMount() {
        const {member} = this.context;
        if (member) {
            this.context.doAction('switchPage', {
                page: 'accountHome'
            });
        }
        
        // Check if Azure AD SSO is available for members
        this.checkAzureSsoStatus();
    }
    
    async checkAzureSsoStatus() {
        try {
            const response = await fetch('/members/api/auth/azure/status');
            if (response.ok) {
                const status = await response.json();
                this.setState({azureSsoEnabled: status.enabled && status.configured});
            }
        } catch (e) {
            // Azure SSO not available
            this.setState({azureSsoEnabled: false});
        }
    }

    handleSignin(e) {
        e.preventDefault();
        this.doSignin();
    }

    doSignin() {
        this.setState((state) => {
            return {
                errors: ValidateInputForm({fields: this.getInputFields({state})})
            };
        }, async () => {
            const {email, phonenumber, errors, token} = this.state;
            const {redirect} = this.context.pageData ?? {};
            const hasFormErrors = (errors && Object.values(errors).filter(d => !!d).length > 0);
            if (!hasFormErrors) {
                this.context.doAction('signin', {email, phonenumber, redirect, token});
            }
        });
    }

    handleInputChange(e, field) {
        const fieldName = field.name;
        this.setState({
            [fieldName]: e.target.value
        });
    }

    onKeyDown(e) {
        // Handles submit on Enter press
        if (e.keyCode === 13){
            this.handleSignin(e);
        }
    }

    getInputFields({state}) {
        const errors = state.errors || {};
        const fields = [
            {
                type: 'email',
                value: state.email,
                placeholder: t('jamie@example.com'),
                label: t('Email'),
                name: 'email',
                required: true,
                errorMessage: errors.email || '',
                autoFocus: true
            },
            {
                type: 'text',
                value: state.phonenumber,
                placeholder: '+1 (123) 456-7890',
                // Doesn't need translation, hidden field
                label: 'Phone number',
                name: 'phonenumber',
                required: false,
                tabIndex: -1,
                autoComplete: 'off',
                hidden: true
            }
        ];
        return fields;
    }

    handleMicrosoftSignin(e) {
        e.preventDefault();
        this.context.doAction('signinWithMicrosoft');
    }

    renderMicrosoftSsoButton() {
        if (!this.state.azureSsoEnabled) {
            return null;
        }

        return (
            <div className="gh-portal-sso-section">
                <button
                    className="gh-portal-btn gh-portal-btn-outline gh-portal-btn-microsoft"
                    data-test-button="signin-microsoft"
                    onClick={e => this.handleMicrosoftSignin(e)}
                    style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '8px',
                        width: '100%',
                        marginBottom: '16px'
                    }}
                >
                    <MicrosoftIcon style={{width: '18px', height: '18px'}} />
                    <span>{t('Sign in with Microsoft')}</span>
                </button>
                <div className="gh-portal-divider" style={{
                    display: 'flex',
                    alignItems: 'center',
                    margin: '16px 0',
                    color: 'var(--grey6)'
                }}>
                    <span style={{
                        flex: 1,
                        height: '1px',
                        backgroundColor: 'var(--grey11)'
                    }}></span>
                    <span style={{padding: '0 12px', fontSize: '13px'}}>{t('or')}</span>
                    <span style={{
                        flex: 1,
                        height: '1px',
                        backgroundColor: 'var(--grey11)'
                    }}></span>
                </div>
            </div>
        );
    }

    renderSubmitButton() {
        const {action} = this.context;
        let retry = false;
        const isRunning = (action === 'signin:running');
        let label = isRunning ? t('Sending login link...') : t('Continue');
        const disabled = isRunning ? true : false;
        if (action === 'signin:failed') {
            label = t('Retry');
            retry = true;
        }
        return (
            <ActionButton
                dataTestId='signin'
                retry={retry}
                style={{width: '100%'}}
                onClick={e => this.handleSignin(e)}
                disabled={disabled}
                brandColor={this.context.brandColor}
                label={label}
                isRunning={isRunning}
            />
        );
    }

    renderSignupMessage() {
        const {brandColor} = this.context;
        return (
            <div className='gh-portal-signup-message'>
                <div>{t('Don\'t have an account?')}</div>
                <button
                    data-test-button='signup-switch'
                    className='gh-portal-btn gh-portal-btn-link'
                    style={{color: brandColor}}
                    onClick={() => this.context.doAction('switchPage', {page: 'signup'})}
                >
                    <span>{t('Sign up')}</span>
                </button>
            </div>
        );
    }

    renderForm() {
        const {site} = this.context;
        const isSignupAvailable = isSignupAllowed({site}) && hasAvailablePrices({site});

        if (!isSigninAllowed({site})) {
            return (
                <section>
                    <div className='gh-portal-section'>
                        <p
                            className='gh-portal-members-disabled-notification'
                            data-testid="members-disabled-notification-text"
                        >
                            {t('Memberships unavailable, contact the owner for access.')}
                        </p>
                    </div>
                </section>
            );
        }

        return (
            <section>
                <div className='gh-portal-section'>
                    {this.renderMicrosoftSsoButton()}
                    <InputForm
                        fields={this.getInputFields({state: this.state})}
                        onChange={(e, field) => this.handleInputChange(e, field)}
                        onKeyDown={(e, field) => this.onKeyDown(e, field)}
                    />
                </div>
                <footer className='gh-portal-signin-footer'>
                    {this.renderSubmitButton()}
                    {isSignupAvailable && this.renderSignupMessage()}
                </footer>
            </section>
        );
    }

    renderSiteIcon() {
        const iconStyle = {};
        const {site} = this.context;
        const siteIcon = site.icon;

        if (siteIcon) {
            iconStyle.backgroundImage = `url(${siteIcon})`;
            return (
                <img className='gh-portal-signup-logo' src={siteIcon} alt={this.context.site.title} />
            );
        } else if (!isSigninAllowed({site})) {
            return (
                <InvitationIcon className='gh-portal-icon gh-portal-icon-invitation' />
            );
        }
        return null;
    }

    renderSiteTitle() {
        const {site} = this.context;
        const siteTitle = site.title;

        if (!isSigninAllowed({site})) {
            return (
                <h1 className='gh-portal-main-title'>{siteTitle}</h1>
            );
        } else {
            return (
                <h1 className='gh-portal-main-title'>{t('Sign in')}</h1>
            );
        }
    }

    renderFormHeader() {
        return (
            <header className='gh-portal-signin-header'>
                {this.renderSiteIcon()}
                {this.renderSiteTitle()}
            </header>
        );
    }

    render() {
        return (
            <>
                <CloseButton />
                <div className='gh-portal-logged-out-form-container'>
                    <div className='gh-portal-content signin'>
                        {this.renderFormHeader()}
                        {this.renderForm()}
                    </div>
                </div>
            </>
        );
    }
}
