// Password Manager Application with Authentication and Supabase Integration
class PasswordManagerApp {
    constructor() {
        // Supabase configuration
        this.supabaseUrl = 'https://auizjjsuowtsqcqkxvau.supabase.co';
        this.supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImF1aXpqanN1b3d0c3FjcWt4dmF1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTUwOTMzMTUsImV4cCI6MjA3MDY2OTMxNX0.TyhJBjVtNy3gIi8sz9cPbP-8D6sLx2iumerK_ARJ4r0';
        this.supabase = null;
        
        // Password manager data
        this.passwords = [];
        this.users = []; // Initialize users array
        this.categories = [
            "Email", "Social Media", "Banking", "Entertainment", "Work", "Shopping", "Other"
        ];
        this.currentView = 'dashboard';
        this.editingId = null;
        this.deleteId = null;
        this.currentUser = null;
        this.isAuthenticated = false;
        
        this.initializeApp();
    }

    // Initialize Supabase connection
    async initializeSupabase() {
        try {
            // Check if Supabase is available
            if (typeof window.supabase !== 'undefined') {
                this.supabase = window.supabase.createClient(this.supabaseUrl, this.supabaseKey);
                console.log('Supabase initialized successfully');
                
                // Check if user is already authenticated
                const { data: { user }, error } = await this.supabase.auth.getUser();
                if (user && !error) {
                    // Also get username from profiles table
                    const { data: profile } = await this.supabase
                        .from('profiles')
                        .select('username')
                        .eq('id', user.id)
                        .single();
                    
                    this.currentUser = {
                        id: user.id,
                        username: profile?.username || user.user_metadata?.username || user.email,
                        email: user.email,
                        createdAt: user.created_at
                    };
                    this.isAuthenticated = true;
                    this.showMainApp();
                    await this.loadUserPasswords();
                }
            } else {
                console.warn('Supabase not available, using local storage');
                this.loadLocalData();
            }
        } catch (error) {
            console.error('Error initializing Supabase:', error);
            this.loadLocalData();
        }
    }

    // Load data from local storage if Supabase is not available
    loadLocalData() {
        const savedPasswords = localStorage.getItem('passwordManagerPasswords');
        const savedUsers = localStorage.getItem('passwordManagerUsers');
        
        if (savedPasswords) {
            this.passwords = JSON.parse(savedPasswords);
        }
        if (savedUsers) {
            this.users = JSON.parse(savedUsers);
        }
    }

    // Save data to local storage as fallback
    saveLocalData() {
        if (!this.supabase) {
            localStorage.setItem('passwordManagerPasswords', JSON.stringify(this.passwords));
            localStorage.setItem('passwordManagerUsers', JSON.stringify(this.users));
        }
    }

    // Load user passwords from Supabase
    async loadUserPasswords() {
        if (!this.supabase || !this.currentUser) return;
        
        try {
            const { data, error } = await this.supabase
                .from('passwords')
                .select('*')
                .eq('user_id', this.currentUser.id);
                
            if (error) throw error;
            
            this.passwords = data.map(password => ({
                id: password.id,
                service: password.service,
                username: password.username,
                password: password.password,
                category: password.category,
                notes: password.notes || '',
                userId: password.user_id,
                dateCreated: password.created_at.slice(0, 10)
            }));
            
            // Update dashboard and tables if we're in the main app
            if (this.currentView === 'dashboard') {
                this.updateDashboard();
            } else if (this.currentView === 'all-passwords') {
                this.updatePasswordsTable();
            }
        } catch (error) {
            console.error('Error loading passwords:', error);
            this.showToast('Error loading passwords', 'error');
        }
    }

    // Save password to Supabase
    async savePasswordToSupabase(passwordData) {
        if (!this.supabase) return null;
        
        try {
            const supabaseData = {
                service: passwordData.service,
                username: passwordData.username,
                password: passwordData.password,
                category: passwordData.category,
                notes: passwordData.notes,
                user_id: this.currentUser.id
            };
            
            if (passwordData.id && this.editingId) {
                // Update existing password
                const { data, error } = await this.supabase
                    .from('passwords')
                    .update(supabaseData)
                    .eq('id', passwordData.id)
                    .eq('user_id', this.currentUser.id)
                    .select()
                    .single();
                    
                if (error) throw error;
                return data;
            } else {
                // Insert new password
                const { data, error } = await this.supabase
                    .from('passwords')
                    .insert(supabaseData)
                    .select()
                    .single();
                    
                if (error) throw error;
                return data;
            }
        } catch (error) {
            console.error('Error saving password:', error);
            throw error;
        }
    }

    // Delete password from Supabase
    async deletePasswordFromSupabase(passwordId) {
        if (!this.supabase) return;
        
        try {
            const { error } = await this.supabase
                .from('passwords')
                .delete()
                .eq('id', passwordId)
                .eq('user_id', this.currentUser.id);
                
            if (error) throw error;
        } catch (error) {
            console.error('Error deleting password:', error);
            throw error;
        }
    }

    // Register user with Supabase - No email verification required
async registerWithSupabase(email, password, username) {
    if (!this.supabase) return null;
    
    try {
        const { data, error } = await this.supabase.auth.signUp({
            email: email,
            password: password,
            options: {
                data: {
                    username: username
                },
                // Disable email confirmation
                emailRedirectTo: null
            }
        });
        
        if (error) throw error;
        
        // Also manually insert into profiles
        if (data.user) {
            try {
                await this.supabase
                    .from('profiles')
                    .insert({
                        id: data.user.id,
                        username: username,
                        email: email
                    });
            } catch (profileError) {
                console.warn('Profile creation failed (trigger might have handled it):', profileError);
            }
        }
        
        return data;
    } catch (error) {
        console.error('Error registering user:', error);
        throw error;
    }
}
    
    // Login user with Supabase - supports both email and username
    async loginWithSupabase(loginInput, password) {
        if (!this.supabase) return null;

        try {
            let email = loginInput;

            // If input doesn't contain '@', treat as username and retrieve email from profiles
            if (!loginInput.includes('@')) {
                const { data: profile, error: profileError } = await this.supabase
                    .from('profiles')
                    .select('email')
                    .eq('username', loginInput)
                    .maybeSingle();

                if (profileError || !profile) {
                    throw new Error('User not found');
                }
                email = profile.email;
            }

            const { data, error } = await this.supabase.auth.signInWithPassword({
                email,
                password
            });

            if (error) throw error;
            return data;

        } catch (error) {
            console.error('Error logging in:', error);
            throw error;
        }
    }

    // Logout user from Supabase
    async logoutFromSupabase() {
        if (!this.supabase) return;
        
        try {
            const { error } = await this.supabase.auth.signOut();
            if (error) throw error;
        } catch (error) {
            console.error('Error logging out:', error);
        }
    }

    // Initialize the application
    async initializeApp() {
        await this.initializeSupabase();
        this.bindAuthEvents();
        this.bindMainAppEvents();
        
        if (!this.isAuthenticated) {
            this.showAuthSection();
        }
    }

    // Authentication Event Bindings
    bindAuthEvents() {
        // Form switches
        const showRegisterForm = document.getElementById('showRegisterForm');
        const showLoginForm = document.getElementById('showLoginForm');
        
        if (showRegisterForm) {
            showRegisterForm.addEventListener('click', (e) => {
                e.preventDefault();
                this.switchAuthForm('register');
            });
        }
        
        if (showLoginForm) {
            showLoginForm.addEventListener('click', (e) => {
                e.preventDefault();
                this.switchAuthForm('login');
            });
        }
        
        // Form submissions
        const loginForm = document.getElementById('loginFormElement');
        const registerForm = document.getElementById('registerFormElement');
        
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleLogin();
            });
        }
        
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleRegistration();
            });
        }
        
        // Password toggle buttons
        document.addEventListener('click', (e) => {
            if (e.target.closest('.toggle-password-btn')) {
                const button = e.target.closest('.toggle-password-btn');
                const target = button.getAttribute('data-target');
                if (target) {
                    this.togglePasswordVisibility(target);
                }
            }
        });
        
        // Real-time validation for registration
        this.bindRegistrationValidation();
        
        // Logout
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => {
                this.handleLogout();
            });
        }
    }

    // Bind registration field validation
    bindRegistrationValidation() {
        const usernameInput = document.getElementById('registerUsername');
        const emailInput = document.getElementById('registerEmail');
        const passwordInput = document.getElementById('registerPassword');
        const confirmPasswordInput = document.getElementById('confirmPassword');
        
        if (usernameInput) {
            usernameInput.addEventListener('input', () => {
                this.validateUsername(usernameInput.value);
            });
        }
        
        if (emailInput) {
            emailInput.addEventListener('input', () => {
                this.validateEmail(emailInput.value);
            });
        }
        
        if (passwordInput) {
            passwordInput.addEventListener('input', () => {
                this.validatePasswordStrength(passwordInput.value);
            });
        }
        
        if (confirmPasswordInput) {
            confirmPasswordInput.addEventListener('input', () => {
                const password = passwordInput ? passwordInput.value : '';
                this.validatePasswordMatch(password, confirmPasswordInput.value);
            });
        }
    }

    // Switch between login and registration forms
    switchAuthForm(formType) {
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        
        if (formType === 'register') {
            if (loginForm) loginForm.classList.remove('active');
            if (registerForm) registerForm.classList.add('active');
        } else {
            if (registerForm) registerForm.classList.remove('active');
            if (loginForm) loginForm.classList.add('active');
        }
    }

    // Toggle password visibility
    togglePasswordVisibility(inputId) {
        const input = document.getElementById(inputId);
        const button = document.querySelector(`[data-target="${inputId}"]`);
        const icon = button ? button.querySelector('i') : null;
        
        if (!input || !icon) return;
        
        if (input.type === 'password') {
            input.type = 'text';
            icon.className = 'fas fa-eye-slash';
        } else {
            input.type = 'password';
            icon.className = 'fas fa-eye';
        }
    }

    // Username validation
    async validateUsername(username) {
        const validation = document.getElementById('usernameValidation');
        if (!validation) return;
        
        if (username.length < 3) {
            validation.textContent = 'Username must be at least 3 characters';
            validation.className = 'field-validation invalid';
            return false;
        }
        
        // Check local users first for demo
        let existingUser = this.users.find(user => 
            user.username.toLowerCase() === username.toLowerCase()
        );
        
        // If using Supabase, also check there
        if (this.supabase && !existingUser) {
            try {
                const { data, error } = await this.supabase
                    .from('profiles')
                    .select('username')
                    .ilike('username', username)
                    .maybeSingle();
                    
                if (data && !error) {
                    existingUser = data;
                }
            } catch (error) {
                // Username not found is expected
            }
        }
        
        if (existingUser) {
            validation.textContent = 'Username already taken';
            validation.className = 'field-validation invalid';
            return false;
        }
        
        validation.textContent = 'Username available';
        validation.className = 'field-validation valid';
        return true;
    }

    // Email validation
    validateEmail(email) {
        const validation = document.getElementById('emailValidation');
        if (!validation) return;
        
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            validation.textContent = 'Please enter a valid email address';
            validation.className = 'field-validation invalid';
            return false;
        }
        
        const existingUser = this.users.find(user => 
            user.email.toLowerCase() === email.toLowerCase()
        );
        
        if (existingUser) {
            validation.textContent = 'Email already registered';
            validation.className = 'field-validation invalid';
            return false;
        }
        
        validation.textContent = 'Email available';
        validation.className = 'field-validation valid';
        return true;
    }

    // Password strength validation
    validatePasswordStrength(password) {
        const strengthBar = document.querySelector('.strength-fill');
        const strengthText = document.querySelector('.strength-text');
        
        if (!strengthBar || !strengthText) return;
        
        let strength = 0;
        let strengthText_content = 'Very weak';
        
        if (password.length >= 6) strength++;
        if (password.length >= 10) strength++;
        if (/[a-z]/.test(password)) strength++;
        if (/[A-Z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[^A-Za-z0-9]/.test(password)) strength++;
        
        strengthBar.className = 'strength-fill';
        
        if (strength >= 6) {
            strengthBar.classList.add('strong');
            strengthText_content = 'Very strong';
        } else if (strength >= 4) {
            strengthBar.classList.add('good');
            strengthText_content = 'Good';
        } else if (strength >= 2) {
            strengthBar.classList.add('fair');
            strengthText_content = 'Fair';
        } else if (strength >= 1) {
            strengthBar.classList.add('weak');
            strengthText_content = 'Weak';
        }
        
        strengthText.textContent = strengthText_content;
        return strength >= 4;
    }

    // Password match validation
    validatePasswordMatch(password, confirmPassword) {
        const validation = document.getElementById('confirmPasswordValidation');
        if (!validation) return;
        
        if (confirmPassword === '') {
            validation.textContent = '';
            validation.className = 'field-validation';
            return false;
        }
        
        if (password !== confirmPassword) {
            validation.textContent = 'Passwords do not match';
            validation.className = 'field-validation invalid';
            return false;
        }
        
        validation.textContent = 'Passwords match';
        validation.className = 'field-validation valid';
        return true;
    }

    // Handle user login
    async handleLogin() {
        const usernameInput = document.getElementById('loginUsername');
        const passwordInput = document.getElementById('loginPassword');
        const submitBtn = document.querySelector('#loginForm .auth-submit-btn');
        
        if (!usernameInput || !passwordInput) return;
        
        const username = usernameInput.value.trim();
        const password = passwordInput.value;
        
        if (!username || !password) {
            this.showToast('Please fill in all fields', 'error');
            return;
        }
        
        // Show loading state
        this.setAuthButtonLoading(submitBtn, true);
        
        try {
            // Try Supabase login first if available
            if (this.supabase) {
                const authData = await this.loginWithSupabase(username, password);
                if (authData && authData.user) {
                    // Get username from profiles table
                    const { data: profile } = await this.supabase
                        .from('profiles')
                        .select('username')
                        .eq('id', authData.user.id)
                        .single();
                    
                    this.currentUser = {
                        id: authData.user.id,
                        username: profile?.username || authData.user.user_metadata?.username || authData.user.email,
                        email: authData.user.email,
                        createdAt: authData.user.created_at
                    };
                    this.isAuthenticated = true;
                    this.showToast(`Welcome back, ${this.currentUser.username}!`, 'success');
                    this.showMainApp();
                    await this.loadUserPasswords();
                    this.setAuthButtonLoading(submitBtn, false);
                    return;
                }
            }
            
            // Fallback to local authentication
            setTimeout(() => {
                const user = this.users.find(user => 
                    (user.username === username || user.email === username) && 
                    user.password === password
                );
                
                if (user) {
                    this.currentUser = user;
                    this.isAuthenticated = true;
                    this.showToast(`Welcome back, ${user.username}!`, 'success');
                    this.showMainApp();
                } else {
                    this.showToast('Invalid username or password', 'error');
                }
                
                this.setAuthButtonLoading(submitBtn, false);
            }, 1000);
        } catch (error) {
            console.error('Login error:', error);
            this.showToast(error.message || 'Login failed. Please try again.', 'error');
            this.setAuthButtonLoading(submitBtn, false);
        }
    }

    // Handle user registration - Simplified without email verification
    async handleRegistration() {
        const usernameInput = document.getElementById('registerUsername');
        const emailInput = document.getElementById('registerEmail');
        const passwordInput = document.getElementById('registerPassword');
        const confirmPasswordInput = document.getElementById('confirmPassword');
        const submitBtn = document.querySelector('#registerForm .auth-submit-btn');
        
        if (!usernameInput || !emailInput || !passwordInput || !confirmPasswordInput) return;
        
        const username = usernameInput.value.trim();
        const email = emailInput.value.trim();
        const password = passwordInput.value;
        const confirmPassword = confirmPasswordInput.value;
        
        // Validate all fields
        const isUsernameValid = await this.validateUsername(username);
        const isEmailValid = this.validateEmail(email);
        const isPasswordStrong = this.validatePasswordStrength(password);
        const isPasswordMatch = this.validatePasswordMatch(password, confirmPassword);
        
        if (!isUsernameValid || !isEmailValid || !isPasswordStrong || !isPasswordMatch) {
            this.showToast('Please fix the validation errors', 'error');
            return;
        }
        
        // Show loading state
        this.setAuthButtonLoading(submitBtn, true);
        
        try {
            // Try Supabase registration first if available
            if (this.supabase) {
                const authData = await this.registerWithSupabase(email, password, username);
                if (authData && authData.user) {
                    // Registration successful - automatically log the user in
                    this.currentUser = {
                        id: authData.user.id,
                        username: username,
                        email: authData.user.email,
                        createdAt: authData.user.created_at
                    };
                    this.isAuthenticated = true;
                    
                    this.showToast(`Welcome to Password Manager, ${username}!`, 'success');
                    this.showMainApp();
                    await this.loadUserPasswords();
                    this.setAuthButtonLoading(submitBtn, false);
                    return;
                }
            }
            
            // Fallback to local registration
            setTimeout(() => {
                const newUser = {
                    id: this.users.length + 1,
                    username,
                    email,
                    password,
                    createdAt: new Date().toISOString().slice(0, 10)
                };
                
                this.users.push(newUser);
                this.saveLocalData();
                
                // Auto-login the user after registration
                this.currentUser = newUser;
                this.isAuthenticated = true;
                
                this.showToast(`Welcome to Password Manager, ${username}!`, 'success');
                this.showMainApp();
                this.setAuthButtonLoading(submitBtn, false);
            }, 1500);
        } catch (error) {
            console.error('Registration error:', error);
            this.showToast(error.message || 'Registration failed. Please try again.', 'error');
            this.setAuthButtonLoading(submitBtn, false);
        }
    }

    // Set authentication button loading state
    setAuthButtonLoading(button, isLoading) {
        if (!button) return;
        
        const btnText = button.querySelector('.btn-text');
        const btnLoading = button.querySelector('.btn-loading');
        
        if (isLoading) {
            button.disabled = true;
            if (btnText) btnText.classList.add('hidden');
            if (btnLoading) btnLoading.classList.remove('hidden');
        } else {
            button.disabled = false;
            if (btnText) btnText.classList.remove('hidden');
            if (btnLoading) btnLoading.classList.add('hidden');
        }
    }

    // Handle user logout
    async handleLogout() {
        try {
            // Logout from Supabase if available
            if (this.supabase) {
                await this.logoutFromSupabase();
            }
        } catch (error) {
            console.error('Logout error:', error);
        }
        
        this.currentUser = null;
        this.isAuthenticated = false;
        this.passwords = [];
        
        this.showToast('Logged out successfully', 'success');
        this.showAuthSection();
        
        // Clear forms
        const loginForm = document.getElementById('loginFormElement');
        const registerForm = document.getElementById('registerFormElement');
        if (loginForm) loginForm.reset();
        if (registerForm) registerForm.reset();
        
        // Reset to login form
        this.switchAuthForm('login');
    }

    // Show authentication section
    showAuthSection() {
        const authSection = document.getElementById('authSection');
        const mainApp = document.getElementById('mainApp');
        
        if (authSection) authSection.style.display = 'flex';
        if (mainApp) mainApp.classList.add('hidden');
    }

    // Show main application
    showMainApp() {
        const authSection = document.getElementById('authSection');
        const mainApp = document.getElementById('mainApp');
        
        if (authSection) authSection.style.display = 'none';
        if (mainApp) mainApp.classList.remove('hidden');
        
        // Update user info
        const currentUserName = document.getElementById('currentUserName');
        if (currentUserName && this.currentUser) {
            currentUserName.textContent = this.currentUser.username;
        }
        
        // Initialize main app
        this.switchView('dashboard');
    }

    // Main Application Event Bindings (existing password manager functionality)
    bindMainAppEvents() {
        // Navigation
        document.addEventListener('click', (e) => {
            const navButton = e.target.closest('.nav-link');
            if (navButton) {
                e.preventDefault();
                const view = navButton.getAttribute('data-view');
                if (view) {
                    this.switchView(view);
                }
            }
        });
        
        // Password form submission
        const passwordForm = document.getElementById('passwordForm');
        if (passwordForm) {
            passwordForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.savePassword();
            });
        }
        
        // Cancel button
        const cancelBtn = document.getElementById('cancelBtn');
        if (cancelBtn) {
            cancelBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.resetForm();
                this.switchView('all-passwords');
            });
        }
        
        // Search functionality
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                const searchTerm = e.target.value;
                const categoryFilter = document.getElementById('categoryFilter');
                const selectedCategory = categoryFilter ? categoryFilter.value : '';
                this.filterPasswords(searchTerm, selectedCategory);
            });
        }
        
        // Category filter
        const categoryFilter = document.getElementById('categoryFilter');
        if (categoryFilter) {
            categoryFilter.addEventListener('change', (e) => {
                const selectedCategory = e.target.value;
                const searchInput = document.getElementById('searchInput');
                const searchTerm = searchInput ? searchInput.value : '';
                this.filterPasswords(searchTerm, selectedCategory);
            });
        }
        
        // Password generator events
        this.bindGeneratorEvents();
        
        // Modal events
        this.bindModalEvents();
        
        // Global click handler for dynamic elements
        document.addEventListener('click', (e) => {
            this.handleGlobalClick(e);
        });
        
        // Form input toggle password visibility
        document.addEventListener('click', (e) => {
            if (e.target.closest('.toggle-password')) {
                const button = e.target.closest('.toggle-password');
                const target = button.getAttribute('data-target');
                if (target) {
                    this.toggleFormPasswordVisibility(target);
                }
            }
        });
    }

    // Toggle password visibility in form
    toggleFormPasswordVisibility(inputId) {
        const input = document.getElementById(inputId);
        const button = document.querySelector(`[data-target="${inputId}"]`);
        const icon = button ? button.querySelector('i') : null;
        
        if (!input || !icon) return;
        
        if (input.type === 'password') {
            input.type = 'text';
            icon.className = 'fas fa-eye-slash';
        } else {
            input.type = 'password';
            icon.className = 'fas fa-eye';
        }
    }

    // Bind password generator events
    bindGeneratorEvents() {
        const generateBtn = document.getElementById('generateNewPassword');
        if (generateBtn) {
            generateBtn.addEventListener('click', () => {
                this.generatePassword();
            });
        }
        
        const copyBtn = document.getElementById('copyGeneratedPassword');
        if (copyBtn) {
            copyBtn.addEventListener('click', () => {
                const password = document.getElementById('generatedPassword').value;
                if (password) {
                    this.copyToClipboard(password, 'Password copied to clipboard!');
                }
            });
        }
        
        const lengthSlider = document.getElementById('lengthSlider');
        if (lengthSlider) {
            lengthSlider.addEventListener('input', (e) => {
                const lengthValue = document.getElementById('lengthValue');
                if (lengthValue) {
                    lengthValue.textContent = e.target.value;
                }
                this.generatePassword();
            });
        }
        
        // Generator checkboxes
        const checkboxes = ['includeUppercase', 'includeLowercase', 'includeNumbers', 'includeSymbols', 'excludeAmbiguous'];
        checkboxes.forEach(id => {
            const checkbox = document.getElementById(id);
            if (checkbox) {
                checkbox.addEventListener('change', () => {
                    this.generatePassword();
                });
            }
        });
        
        // Generate password button in add password form
        const generatePasswordBtn = document.getElementById('generatePasswordBtn');
        if (generatePasswordBtn) {
            generatePasswordBtn.addEventListener('click', (e) => {
                e.preventDefault();
                const password = this.generatePasswordString();
                const passwordInput = document.getElementById('passwordInput');
                if (passwordInput) {
                    passwordInput.value = password;
                }
            });
        }
    }

    // Bind modal events
    bindModalEvents() {
        const cancelDelete = document.getElementById('cancelDelete');
        if (cancelDelete) {
            cancelDelete.addEventListener('click', () => {
                this.hideModal();
            });
        }
        
        const confirmDelete = document.getElementById('confirmDelete');
        if (confirmDelete) {
            confirmDelete.addEventListener('click', () => {
                this.confirmDelete();
            });
        }
        
        const modalBackdrop = document.querySelector('.modal-backdrop');
        if (modalBackdrop) {
            modalBackdrop.addEventListener('click', () => {
                this.hideModal();
            });
        }
    }

    // Handle global clicks for dynamic elements
    handleGlobalClick(e) {
        const target = e.target;
        
        // Toggle password visibility in table
        if (target.closest('.toggle-password') && !target.closest('.password-input-group')) {
            e.preventDefault();
            this.togglePasswordVisibilityInTable(target.closest('.toggle-password'));
            return;
        }
        
        // Copy username
        if (target.closest('[data-action="copy-username"]')) {
            e.preventDefault();
            const username = target.closest('[data-action="copy-username"]').dataset.value;
            this.copyToClipboard(username, 'Username copied!');
            return;
        }
        
        // Copy password
        if (target.closest('[data-action="copy-password"]')) {
            e.preventDefault();
            const password = target.closest('[data-action="copy-password"]').dataset.value;
            this.copyToClipboard(password, 'Password copied!');
            return;
        }
        
        // Edit password
        if (target.closest('[data-action="edit"]')) {
            e.preventDefault();
            const id = parseInt(target.closest('[data-action="edit"]').dataset.id);
            this.editPassword(id);
            return;
        }
        
        // Delete password
        if (target.closest('[data-action="delete"]')) {
            e.preventDefault();
            const id = parseInt(target.closest('[data-action="delete"]').dataset.id);
            this.showDeleteModal(id);
            return;
        }
        
        // Category card click
        if (target.closest('.category-card')) {
            const card = target.closest('.category-card');
            const category = card.querySelector('h3').textContent;
            this.filterByCategory(category);
            return;
        }
    }

    // Switch between views
    switchView(view) {
        if (!this.isAuthenticated) return;
        
        // Update navigation active state
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        const activeLink = document.querySelector(`[data-view="${view}"]`);
        if (activeLink) {
            activeLink.classList.add('active');
        }
        
        // Update content visibility
        document.querySelectorAll('.view').forEach(v => {
            v.classList.remove('active');
        });
        const activeView = document.getElementById(view);
        if (activeView) {
            activeView.classList.add('active');
        } else {
            return;
        }
        
        this.currentView = view;
        
        // Update view-specific content
        setTimeout(() => {
            switch(view) {
                case 'dashboard':
                    this.updateDashboard();
                    break;
                case 'all-passwords':
                    this.updatePasswordsTable();
                    this.populateCategoryFilter();
                    break;
                case 'add-password':
                    this.resetForm();
                    this.populateCategorySelect();
                    break;
                case 'generate-password':
                    this.initializeGenerator();
                    break;
                case 'categories':
                    this.updateCategoriesView();
                    break;
            }
        }, 50);
    }

    // Get user-specific passwords
    getUserPasswords() {
        if (!this.currentUser) return [];
        return this.passwords.filter(p => p.userId === this.currentUser.id);
    }

    // Initialize password generator
    initializeGenerator() {
        const lengthSlider = document.getElementById('lengthSlider');
        const lengthValue = document.getElementById('lengthValue');
        
        if (lengthSlider && lengthValue) {
            lengthValue.textContent = lengthSlider.value;
        }
        
        this.generatePassword();
    }

    // Update dashboard stats and recent passwords
    updateDashboard() {
        const userPasswords = this.getUserPasswords();
        
        const totalPasswords = document.getElementById('totalPasswords');
        const totalCategories = document.getElementById('totalCategories');
        const recentlyAdded = document.getElementById('recentlyAdded');
        
        if (totalPasswords) totalPasswords.textContent = userPasswords.length;
        if (totalCategories) totalCategories.textContent = new Set(userPasswords.map(p => p.category)).size;
        
        const thisMonth = new Date().toISOString().slice(0, 7);
        const recentCount = userPasswords.filter(p => p.dateCreated.startsWith(thisMonth)).length;
        if (recentlyAdded) recentlyAdded.textContent = recentCount;
        
        // Show recent passwords
        const recentPasswords = userPasswords.slice(-3).reverse();
        const recentList = document.getElementById('recentPasswordsList');
        
        if (recentList) {
            recentList.innerHTML = '';
            recentPasswords.forEach(password => {
                const item = document.createElement('div');
                item.className = 'password-item';
                item.innerHTML = `
                    <div class="password-item-info">
                        <strong>${this.escapeHtml(password.service)}</strong>
                        <span>${this.escapeHtml(password.username)}</span>
                    </div>
                    <span class="password-item-date">${password.dateCreated}</span>
                `;
                recentList.appendChild(item);
            });
            
            if (recentPasswords.length === 0) {
                recentList.innerHTML = '<p>No passwords added yet.</p>';
            }
        }
    }

    // Update categories view
    updateCategoriesView() {
        const userPasswords = this.getUserPasswords();
        const categoriesGrid = document.getElementById('categoriesGrid');
        
        if (!categoriesGrid) return;
        
        categoriesGrid.innerHTML = '';
        
        this.categories.forEach(category => {
            const count = userPasswords.filter(p => p.category === category).length;
            const card = document.createElement('div');
            card.className = 'category-card';
            card.innerHTML = `
                <h3>${category}</h3>
                <p>${count} password${count !== 1 ? 's' : ''}</p>
            `;
            categoriesGrid.appendChild(card);
        });
    }

    // Populate category select dropdown
    populateCategorySelect() {
        const categorySelect = document.getElementById('categoryInput');
        if (!categorySelect) return;
        
        // Clear existing options except the first one
        categorySelect.innerHTML = '<option value="">Select a category</option>';
        
        // Add category options
        this.categories.forEach(category => {
            const option = document.createElement('option');
            option.value = category;
            option.textContent = category;
            categorySelect.appendChild(option);
        });
    }

    // Populate category filter dropdown
    populateCategoryFilter() {
        const categoryFilter = document.getElementById('categoryFilter');
        if (!categoryFilter) return;
        
        // Clear existing options except the first one
        categoryFilter.innerHTML = '<option value="">All Categories</option>';
        
        // Add category options
        this.categories.forEach(category => {
            const option = document.createElement('option');
            option.value = category;
            option.textContent = category;
            categoryFilter.appendChild(option);
        });
    }

    // Generate password for the generator view
    generatePassword() {
        const password = this.generatePasswordString();
        const generatedPasswordInput = document.getElementById('generatedPassword');
        if (generatedPasswordInput) {
            generatedPasswordInput.value = password;
        }
    }

    // Generate password string based on options
    generatePasswordString() {
        const lengthSlider = document.getElementById('lengthSlider');
        const includeUppercase = document.getElementById('includeUppercase');
        const includeLowercase = document.getElementById('includeLowercase');
        const includeNumbers = document.getElementById('includeNumbers');
        const includeSymbols = document.getElementById('includeSymbols');
        const excludeAmbiguous = document.getElementById('excludeAmbiguous');
        
        const length = lengthSlider ? parseInt(lengthSlider.value) : 12;
        const useUppercase = includeUppercase ? includeUppercase.checked : true;
        const useLowercase = includeLowercase ? includeLowercase.checked : true;
        const useNumbers = includeNumbers ? includeNumbers.checked : true;
        const useSymbols = includeSymbols ? includeSymbols.checked : true;
        const excludeAmbiguousChars = excludeAmbiguous ? excludeAmbiguous.checked : false;
        
        let charset = '';
        
        if (useUppercase) {
            charset += excludeAmbiguousChars ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        }
        
        if (useLowercase) {
            charset += excludeAmbiguousChars ? 'abcdefghjkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
        }
        
        if (useNumbers) {
            charset += excludeAmbiguousChars ? '23456789' : '0123456789';
        }
        
        if (useSymbols) {
            charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
        }
        
        if (charset === '') {
            // If no character set is selected, use a default
            charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        }
        
        let password = '';
        for (let i = 0; i < length; i++) {
            const randomIndex = Math.floor(Math.random() * charset.length);
            password += charset[randomIndex];
        }
        
        return password;
    }

    // Save password (add or update)
    async savePassword() {
        const serviceInput = document.getElementById('serviceInput');
        const usernameInput = document.getElementById('usernameInput');
        const passwordInput = document.getElementById('passwordInput');
        const categoryInput = document.getElementById('categoryInput');
        const notesInput = document.getElementById('notesInput');
        
        if (!serviceInput || !usernameInput || !passwordInput || !categoryInput) return;
        
        const service = serviceInput.value.trim();
        const username = usernameInput.value.trim();
        const password = passwordInput.value;
        const category = categoryInput.value;
        const notes = notesInput ? notesInput.value.trim() : '';
        
        if (!service || !username || !password || !category) {
            this.showToast('Please fill in all required fields', 'error');
            return;
        }
        
        const passwordData = {
            service,
            username,
            password,
            category,
            notes,
            userId: this.currentUser.id,
            dateCreated: new Date().toISOString().slice(0, 10)
        };
        
        if (this.editingId) {
            passwordData.id = this.editingId;
        }
        
        try {
            // Try to save to Supabase first
            if (this.supabase) {
                const savedPassword = await this.savePasswordToSupabase(passwordData);
                if (savedPassword) {
                    if (this.editingId) {
                        // Update existing password in local array
                        const index = this.passwords.findIndex(p => p.id === this.editingId);
                        if (index !== -1) {
                            this.passwords[index] = {
                                id: savedPassword.id,
                                service: savedPassword.service,
                                username: savedPassword.username,
                                password: savedPassword.password,
                                category: savedPassword.category,
                                notes: savedPassword.notes || '',
                                userId: savedPassword.user_id,
                                dateCreated: savedPassword.created_at.slice(0, 10)
                            };
                        }
                        this.showToast('Password updated successfully!', 'success');
                    } else {
                        // Add new password to local array
                        this.passwords.push({
                            id: savedPassword.id,
                            service: savedPassword.service,
                            username: savedPassword.username,
                            password: savedPassword.password,
                            category: savedPassword.category,
                            notes: savedPassword.notes || '',
                            userId: savedPassword.user_id,
                            dateCreated: savedPassword.created_at.slice(0, 10)
                        });
                        this.showToast('Password saved successfully!', 'success');
                    }
                    
                    this.resetForm();
                    this.switchView('all-passwords');
                    return;
                }
            }
            
            // Fallback to local storage
            if (this.editingId) {
                const index = this.passwords.findIndex(p => p.id === this.editingId);
                if (index !== -1) {
                    this.passwords[index] = { ...passwordData, id: this.editingId };
                }
                this.showToast('Password updated successfully!', 'success');
            } else {
                passwordData.id = Date.now();
                this.passwords.push(passwordData);
                this.showToast('Password saved successfully!', 'success');
            }
            
            this.saveLocalData();
            this.resetForm();
            this.switchView('all-passwords');
            
        } catch (error) {
            console.error('Error saving password:', error);
            this.showToast('Error saving password. Please try again.', 'error');
        }
    }

    // Reset form
    resetForm() {
        const form = document.getElementById('passwordForm');
        if (form) form.reset();
        
        const formTitle = document.getElementById('formTitle');
        if (formTitle) formTitle.textContent = 'Add Password';
        
        this.editingId = null;
    }

    // Update passwords table
    updatePasswordsTable() {
        const tableBody = document.getElementById('passwordTableBody');
        if (!tableBody) return;
        
        const userPasswords = this.getUserPasswords();
        tableBody.innerHTML = '';
        
        if (userPasswords.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="5" class="no-passwords">
                        <p>No passwords found. <a href="#" onclick="window.passwordManagerApp.switchView('add-password')">Add your first password</a></p>
                    </td>
                </tr>
            `;
            return;
        }
        
        userPasswords.forEach(password => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${this.escapeHtml(password.service)}</td>
                <td>
                    ${this.escapeHtml(password.username)}
                    <button class="btn btn--sm btn--icon" data-action="copy-username" data-value="${this.escapeHtml(password.username)}">
                        <i class="fas fa-copy"></i>
                    </button>
                </td>
                <td class="password-cell">
                    <span class="password-value">••••••••</span>
                    <button class="btn btn--sm btn--icon toggle-password" data-password="${this.escapeHtml(password.password)}">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn--sm btn--icon" data-action="copy-password" data-value="${this.escapeHtml(password.password)}">
                        <i class="fas fa-copy"></i>
                    </button>
                </td>
                <td>
                    <span class="category-badge">${this.escapeHtml(password.category)}</span>
                </td>
                <td class="actions-cell">
                    <button class="btn btn--sm btn--icon" data-action="edit" data-id="${password.id}">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn--sm btn--icon btn--danger" data-action="delete" data-id="${password.id}">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            `;
            tableBody.appendChild(row);
        });
    }

    // Toggle password visibility in table
    togglePasswordVisibilityInTable(button) {
        const passwordCell = button.closest('.password-cell');
        const passwordValue = passwordCell.querySelector('.password-value');
        const icon = button.querySelector('i');
        
        if (!passwordValue || !icon) return;
        
        if (passwordValue.textContent === '••••••••') {
            passwordValue.textContent = button.dataset.password;
            icon.className = 'fas fa-eye-slash';
        } else {
            passwordValue.textContent = '••••••••';
            icon.className = 'fas fa-eye';
        }
    }

    // Edit password
    editPassword(id) {
        const password = this.passwords.find(p => p.id === id);
        if (!password) return;
        
        this.editingId = id;
        
        const serviceInput = document.getElementById('serviceInput');
        const usernameInput = document.getElementById('usernameInput');
        const passwordInput = document.getElementById('passwordInput');
        const categoryInput = document.getElementById('categoryInput');
        const notesInput = document.getElementById('notesInput');
        const formTitle = document.getElementById('formTitle');
        
        if (serviceInput) serviceInput.value = password.service;
        if (usernameInput) usernameInput.value = password.username;
        if (passwordInput) passwordInput.value = password.password;
        if (categoryInput) categoryInput.value = password.category;
        if (notesInput) notesInput.value = password.notes || '';
        if (formTitle) formTitle.textContent = 'Edit Password';
        
        this.switchView('add-password');
    }

    // Show delete modal
    showDeleteModal(id) {
        this.deleteId = id;
        const modal = document.getElementById('deleteModal');
        if (modal) {
            modal.classList.remove('hidden');
        }
    }

    // Hide modal
    hideModal() {
        const modal = document.getElementById('deleteModal');
        if (modal) {
            modal.classList.add('hidden');
        }
        this.deleteId = null;
    }

    // Confirm delete
    async confirmDelete() {
        if (!this.deleteId) return;
        
        try {
            // Try to delete from Supabase first
            if (this.supabase) {
                await this.deletePasswordFromSupabase(this.deleteId);
            }
            
            // Remove from local array
            this.passwords = this.passwords.filter(p => p.id !== this.deleteId);
            this.saveLocalData();
            
            this.showToast('Password deleted successfully', 'success');
            this.hideModal();
            
            // Update current view
            if (this.currentView === 'all-passwords') {
                this.updatePasswordsTable();
            } else if (this.currentView === 'dashboard') {
                this.updateDashboard();
            }
            
        } catch (error) {
            console.error('Error deleting password:', error);
            this.showToast('Error deleting password. Please try again.', 'error');
        }
    }

    // Filter passwords
    filterPasswords(searchTerm = '', category = '') {
        const userPasswords = this.getUserPasswords();
        const filteredPasswords = userPasswords.filter(password => {
            const matchesSearch = !searchTerm || 
                password.service.toLowerCase().includes(searchTerm.toLowerCase()) ||
                password.username.toLowerCase().includes(searchTerm.toLowerCase());
            
            const matchesCategory = !category || password.category === category;
            
            return matchesSearch && matchesCategory;
        });
        
        // Update table with filtered results
        const tableBody = document.getElementById('passwordTableBody');
        if (!tableBody) return;
        
        tableBody.innerHTML = '';
        
        if (filteredPasswords.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="5" class="no-passwords">
                        <p>No passwords match your search criteria.</p>
                    </td>
                </tr>
            `;
            return;
        }
        
        filteredPasswords.forEach(password => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${this.escapeHtml(password.service)}</td>
                <td>
                    ${this.escapeHtml(password.username)}
                    <button class="btn btn--sm btn--icon" data-action="copy-username" data-value="${this.escapeHtml(password.username)}">
                        <i class="fas fa-copy"></i>
                    </button>
                </td>
                <td class="password-cell">
                    <span class="password-value">••••••••</span>
                    <button class="btn btn--sm btn--icon toggle-password" data-password="${this.escapeHtml(password.password)}">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn--sm btn--icon" data-action="copy-password" data-value="${this.escapeHtml(password.password)}">
                        <i class="fas fa-copy"></i>
                    </button>
                </td>
                <td>
                    <span class="category-badge">${this.escapeHtml(password.category)}</span>
                </td>
                <td class="actions-cell">
                    <button class="btn btn--sm btn--icon" data-action="edit" data-id="${password.id}">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn--sm btn--icon btn--danger" data-action="delete" data-id="${password.id}">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            `;
            tableBody.appendChild(row);
        });
    }

    // Filter by category (called when category card is clicked)
    filterByCategory(category) {
        this.switchView('all-passwords');
        
        setTimeout(() => {
            const categoryFilter = document.getElementById('categoryFilter');
            if (categoryFilter) {
                categoryFilter.value = category;
                this.filterPasswords('', category);
            }
        }, 100);
    }

    // Copy to clipboard
    async copyToClipboard(text, message) {
        try {
            await navigator.clipboard.writeText(text);
            this.showToast(message, 'success');
        } catch (err) {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            textArea.style.top = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            
            try {
                document.execCommand('copy');
                this.showToast(message, 'success');
            } catch (err) {
                this.showToast('Failed to copy to clipboard', 'error');
            }
            
            document.body.removeChild(textArea);
        }
    }

    // Show toast notification
    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icon = type === 'success' ? 'check-circle' : 
                     type === 'error' ? 'exclamation-circle' : 
                     type === 'warning' ? 'exclamation-triangle' : 'info-circle';
        
        toast.innerHTML = `
            <i class="fas fa-${icon}"></i>
            ${message}
        `;
        
        const container = document.getElementById('toastContainer');
        if (container) {
            container.appendChild(toast);
            
            setTimeout(() => {
                if (toast.parentElement) {
                    toast.remove();
                }
            }, 3000);
        }
    }

    // Escape HTML to prevent XSS
    escapeHtml(text) {
        if (typeof text !== 'string') return text;
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.passwordManagerApp = new PasswordManagerApp();
});
