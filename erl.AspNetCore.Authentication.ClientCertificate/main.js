var app = new Vue({
    el: '#app',
    data: {
        filter: '',
        availableRoles: [],
        selectedRole: '',
        description: '',
        password: '',
        errorMessage: '',
        certificateList: [],
        validFor: 12,
        uploadFormVisible: false,
        thumbprint: '',
        descriptionError: '',
        roleError: '',
        notAfterError: '',
        passwordError: '',
        certificateError: ''
    },
    created: function() {
        this.refreshAvailableRoles();
        this.refreshCertificateList();
    },
    mounted: function () {
        var me = this;
        window.jQuery('#generate-modal, #upload-modal, #edit-certificate, #disable-certificate').on('hide.bs.modal',
            function() {
                me.resetForm();
            });

        window.jQuery('#edit-certificate').on('show.bs.modal',
            function(event) {
                var fromTarget = window.jQuery(event.relatedTarget);
                me.thumbprint = fromTarget.data('thumbprint');
                me.selectedRole = fromTarget.data('role');
                me.description = fromTarget.data('description');
            });

        window.jQuery('#disable-certificate').on('show.bs.modal',
            function(event) {
                var fromTarget = window.jQuery(event.relatedTarget);
                me.thumbprint = fromTarget.data('thumbprint');
            });

        window.jQuery('form').on('submit',
            function(event) {
                event.preventDefault();
            });
    },
    filters: {
        formatDate: function (rawDate) {
            var date = new Date(rawDate);

            var monthNames = [
                "January", "February", "March",
                "April", "May", "June", "July",
                "August", "September", "October",
                "November", "December"
            ];

            var day = date.getDate();
            var monthIndex = date.getMonth();
            var year = date.getFullYear();

            return day + ' ' + monthNames[monthIndex] + ' ' + year;
        }
    },
    computed: {
        filteredCertificates: function() {
            if (this.filter === '') return this.certificateList;

            var me = this;
            return this.certificateList.filter(function (item) {
                return item.thumbprint.toLowerCase().indexOf(me.filter.toLowerCase()) > -1
                    || item.role.toLowerCase().indexOf(me.filter.toLowerCase()) > -1
                    || item.description.toLowerCase().indexOf(me.filter.toLowerCase()) > -1
                    || me.formatDateFunc(item.notAfter).toLowerCase().indexOf(me.filter.toLowerCase()) > -1;
            });
        }
    },
    methods: {
        resetErrors: function() {
            this.descriptionError = '';
            this.roleError = '';
            this.notAfterError = '';
            this.passwordError = '';
            this.certificateError = '';
        },
        isNumber: function (evt) {
            evt = (evt) ? evt : window.event;
            var charCode = (evt.which) ? evt.which : evt.keyCode;
            if ((charCode > 31 && (charCode < 48 || charCode > 57)) && charCode !== 46) {
                evt.preventDefault();
                return false;
            } else {
                return true;
            }
        },
        formatDateFunc: function (rawDate) {
            var date = new Date(rawDate);

            var monthNames = [
                "January", "February", "March",
                "April", "May", "June", "July",
                "August", "September", "October",
                "November", "December"
            ];

            var day = date.getDate();
            var monthIndex = date.getMonth();
            var year = date.getFullYear();

            return day + ' ' + monthNames[monthIndex] + ' ' + year;
        },
        refreshAvailableRoles: function() {
            var me = this;
            window.axios
                .get('/api/ClientCertificate/GetAllRoles')
                .then(function(response) {
                    me.availableRoles = response.data.sort((a, b) => a.toLocaleLowerCase().localeCompare(b.toLocaleLowerCase()));
                });
        },
        refreshCertificateList: function() {
            var me = this;
            window.axios
                .get('/api/ClientCertificate/GetAll')
                .then(function(response) {
                    me.certificateList = response.data.sort((a, b) => a.description.toLocaleLowerCase().localeCompare(b.description.toLocaleLowerCase()));
                });
        },
        generateCertificate: function() {
            var me = this;

            me.resetErrors();

            window.axios({
                url: '/api/ClientCertificate/Generate',
                method: 'POST',
                accept: 'application/octet-stream application/json',
                responseType: 'blob',
                data: {
                    Description: me.description,
                    Role: me.selectedRole,
                    Password: me.password,
                    ValidForMonths: Number(me.validFor)
                }
            }).then(function (response) {
                var url = window.URL.createObjectURL(new Blob([response.data]));
                var link = document.createElement('a');
                link.href = url;
                link.setAttribute('download', me.description + ".zip");
                document.body.appendChild(link);
                link.click();

                me.refreshCertificateList();
                me.resetForm();
                window.jQuery('#generate-modal').modal('hide');
            }).catch(function (errorResponse) {
                console.log('errorResponse', errorResponse);
                var reader = new FileReader();
                // fatal: reader.addEventListener('abort', reject)
                // fatal: reader.addEventListener('error', reject)
                reader.addEventListener('loadend', () => {
                    var errors = JSON.parse(reader.result);
                    me.setErrors(errors);
                });

                reader.readAsText(errorResponse.response.data);
            });
        },
        setErrors: function (errors) {
            this.resetErrors();
            for (var fieldName in errors) {
                if (Object.prototype.hasOwnProperty.call(errors, fieldName)) {
                    var errorText = errors[fieldName][0];
                    console.log('errorText', errorText);
                    fieldName = fieldName[0].toLowerCase() + fieldName.substring(1) + "Error";
                    this[fieldName] = errorText;
                }
            }
        },
        updateCertificate: function() {
            var me = this;
            window.axios.post('/api/ClientCertificate/Update',
                    {
                        Thumbprint: me.thumbprint,
                        Role: me.selectedRole,
                        Description: me.description
                    })
                .then(function() {
                    me.resetForm();
                    me.refreshCertificateList();
                    window.jQuery('#edit-certificate').modal('hide');
                })
                .catch(function (error) {
                    me.setErrors(error.response.data);
                });
        },
        removeCertificate: function() {
            var me = this;
            window.axios.post('/api/ClientCertificate/RemoveCertificate',
                    {
                        Thumbprint: me.thumbprint
                    })
                .then(function () {
                    me.refreshCertificateList();
                    me.resetForm();
                    window.jQuery('#disable-certificate').modal('hide');
                })
                .catch(function (error) {
                    me.setErrors(error.response.data);
                });
        },
        resetForm: function() {
            this.description = '';
            this.selectedRole = '';
            this.password = '';
            this.errorMessage = '';
            this.validFor = 12;
            this.thumbprint = '';
            document.querySelector('#cert-file').value = '';

            this.resetErrors();
        },
        submitCertificateUpload: function() {
            var me = this;
            var file = document.querySelector('#cert-file').files[0];
            
            if (file === undefined) {
                me.setErrors({ "Certificate": ["Select a certificate file"] });
                return;
            }

            var reader = new FileReader();
            reader.readAsDataURL(file);
            reader.onload = function () {
                // remove metadata
                var encoded = reader.result.toString().replace(/^data:(.*,)?/, '');
                if ((encoded.length % 4) > 0) {
                    encoded += '='.repeat(4 - (encoded.length % 4));
                }

                window.axios.post('/api/ClientCertificate/Upload',
                        {
                            Description: me.description,
                            Role: me.selectedRole,
                            Password: me.password,
                            CertificateEncoded: encoded
                        })
                    .then(function() {
                        me.resetForm();
                        me.refreshCertificateList();
                        window.jQuery('#upload-modal').modal('hide');
                    })
                    .catch(function (error) {
                        me.setErrors(error.response.data);
                    });
            };
            reader.onerror = function (error) {
                console.log('Error: ', error);
            };
        },
        setClipboard: function (srcText) {
            navigator.clipboard.writeText(srcText)
                .then(function () { }
                    , function (err) {
                console.error('Async: Could not copy text: ', err);
            });
        }
    }
});