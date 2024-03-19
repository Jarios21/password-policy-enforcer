class PasswordPolicy {
    constructor(options) {
      this.options = {
        minLength: 8,
        maxLength: 128,
        requireNumbers: true,
        requireLowercase: true,
        requireUppercase: true,
        requireSpecialCharacters: true,
        customValidations: [], // Array of custom validation functions
        ...options,
      };
    }
  
    validate(password) {
      const errors = [];
  
      // Predefined validations
      this.checkLength(password, errors);
      this.checkCharacterRequirements(password, errors);
  
      // Custom validations
      this.options.customValidations.forEach(validation => {
        const error = validation(password);
        if (error) errors.push(error);
      });
  
      return {
        isValid: errors.length === 0,
        errors,
      };
    }
  
    checkLength(password, errors) {
      if (password.length < this.options.minLength) {
        errors.push(`Password must be at least ${this.options.minLength} characters long.`);
      }
  
      if (password.length > this.options.maxLength) {
        errors.push(`Password must be no more than ${this.options.maxLength} characters long.`);
      }
    }
  
    checkCharacterRequirements(password, errors) {
      if (this.options.requireNumbers && !/\d/.test(password)) {
        errors.push("Password must contain at least one number.");
      }
  
      if (this.options.requireLowercase && !/[a-z]/.test(password)) {
        errors.push("Password must contain at least one lowercase letter.");
      }
  
      if (this.options.requireUppercase && !/[A-Z]/.test(password)) {
        errors.push("Password must contain at least one uppercase letter.");
      }
  
      if (
        this.options.requireSpecialCharacters &&
        !/[!@#$%^&*(),.?":{}|<>]/.test(password)
      ) {
        errors.push("Password must contain at least one special character.");
      }
    }
  }
  
  module.exports = PasswordPolicy;