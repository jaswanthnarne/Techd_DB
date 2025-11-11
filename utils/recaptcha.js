export const verifyRecaptcha = async (recaptchaToken) => {
  try {
    const secretKey = process.env.RECAPTCHA_SECRET_KEY;

    // Build URL with query parameters
    const url = new URL("https://www.google.com/recaptcha/api/siteverify");
    url.searchParams.append("secret", secretKey);
    url.searchParams.append("response", recaptchaToken);

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });

    if (!response.ok) {
      throw new `Error(HTTP error! status: ${response.status})`;
    }

    const data = await response.json();
    const { success, score, action, "error-codes": errorCodes } = data;

    return {
      success,
      score,
      action,
      errorCodes,
    };
  } catch (error) {
    console.error("reCAPTCHA verification error:", error);
    return {
      success: false,
      error: "Failed to verify reCAPTCHA",
    };
  }
};