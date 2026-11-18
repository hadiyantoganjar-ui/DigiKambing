import { initializeApp, getApps, getApp } from 'firebase/app';
import {
  getAuth,
  signInWithPopup,
  GoogleAuthProvider,
  onAuthStateChanged,
  User,
  signOut,
} from 'firebase/auth';
import firebaseConfig from '../../firebase-applet-config.json';

// Workspace OAuth Scopes
export const SCOPES = [
  'https://www.googleapis.com/auth/drive',
  'https://www.googleapis.com/auth/drive.file',
  'https://www.googleapis.com/auth/drive.readonly',
  'https://www.googleapis.com/auth/spreadsheets',
  'https://www.googleapis.com/auth/spreadsheets.readonly',
];

// Initialize Firebase App
const app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApp();
export const auth = getAuth(app);

const provider = new GoogleAuthProvider();
SCOPES.forEach((scope) => {
  provider.addScope(scope);
});
provider.setCustomParameters({
  prompt: 'select_account',
});

// Flag to indicate if in the middle of sign-in flow
let isSigningIn = false;
// Cache the access token strictly in-memory (never in localStorage/sessionStorage)
let cachedAccessToken: string | null = null;

/**
 * Listen to Firebase Auth state changes
 */
export const initAuth = (
  onAuthSuccess?: (user: User, token: string) => void,
  onAuthFailure?: () => void
) => {
  return onAuthStateChanged(auth, async (user: User | null) => {
    if (user) {
      if (cachedAccessToken) {
        if (onAuthSuccess) onAuthSuccess(user, cachedAccessToken);
      } else if (!isSigningIn) {
        // Token might have expired or refreshed; sign in popup or user action needed for full OAuth token
        if (onAuthFailure) onAuthFailure();
      }
    } else {
      cachedAccessToken = null;
      if (onAuthFailure) onAuthFailure();
    }
  });
};

/**
 * Sign in with Google Popup and obtain access token with requested scopes
 */
export const googleSignIn = async (): Promise<{ user: User; accessToken: string } | null> => {
  try {
    isSigningIn = true;
    const result = await signInWithPopup(auth, provider);
    const credential = GoogleAuthProvider.credentialFromResult(result);
    if (!credential?.accessToken) {
      throw new Error('Gagal memperoleh OAuth access token dari Google');
    }

    cachedAccessToken = credential.accessToken;
    return { user: result.user, accessToken: cachedAccessToken };
  } catch (error: any) {
    // auth/popup-closed-by-user and auth/cancelled-popup-request occur when the user
    // dismisses or closes the popup window before finishing authentication.
    // This is an intentional cancellation, not an application crash.
    if (
      error?.code === 'auth/popup-closed-by-user' ||
      error?.code === 'auth/cancelled-popup-request'
    ) {
      return null;
    }

    if (error?.code === 'auth/popup-blocked') {
      const blockedErr = new Error('Jendela pop-up login Google diblokir oleh peramban (browser). Harap izinkan pop-up pada situs ini dan coba kembali.');
      (blockedErr as any).code = 'auth/popup-blocked';
      throw blockedErr;
    }

    console.warn('Google Sign-in status:', error?.message || error);
    throw error;
  } finally {
    isSigningIn = false;
  }
};

/**
 * Get current in-memory cached access token
 */
export const getAccessToken = async (): Promise<string | null> => {
  return cachedAccessToken;
};

/**
 * Sign out and clear cached token
 */
export const googleSignOut = async (): Promise<void> => {
  try {
    await signOut(auth);
  } finally {
    cachedAccessToken = null;
  }
};
