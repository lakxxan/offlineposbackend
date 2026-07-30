const mysql = require('mysql2/promise');
const { schema } = require('./schema');
const crypto = require('crypto');

function hashPassword(password) {
    if (!password) return '';
    if (password.length === 64) return password; // Already hashed
    return crypto.createHash('sha256').update(password).digest('hex');
}

exports.handler = async (event) => {
    const headers = {
        "Content-Type": "application/json"
    };

    // 2. Handle Health Check (Browser GET request)
    if (!event.body || event.httpMethod === 'GET') {
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ status: "success", message: "Backend is Live" })
        };
    }

    let connection;
    try {
        const body = JSON.parse(event.body);
        const { action, shopName, adminEmail, adminPassword, email, password } = body;

        const dbConfig = {
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            port: process.env.DB_PORT || 4000,
            connectTimeout: 15000,
            dateStrings: true,
            timezone: '+00:00',
            ssl: {
                minVersion: 'TLSv1.2',
                rejectUnauthorized: true
            }
        };

        console.log("Action:", action, "| Email:", email || adminEmail);
        console.log("Connecting to Database...");
        connection = await mysql.createConnection(dbConfig);
        await connection.query("SET time_zone = '+00:00'");

        // --- AUTH ACTION (Unified Login) ---
        if (action === 'login') {
            console.log("Processing Login...");

            // [FIX] Ensure salespro_central_admin DB and tables exist before querying
            await connection.execute(`CREATE DATABASE IF NOT EXISTS salespro_central_admin`);
            await connection.execute(`
                CREATE TABLE IF NOT EXISTS salespro_central_admin.super_admins (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )
            `);
            await connection.execute(`
                CREATE TABLE IF NOT EXISTS salespro_central_admin.user_to_shop_mapping (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    db_name VARCHAR(255) NOT NULL
                )
            `);

            // 1. Check Super Admin
            const [superAdmins] = await connection.execute(
                'SELECT * FROM salespro_central_admin.super_admins WHERE email = ? AND password = ?',
                [email, hashPassword(password)]
            );

            if (superAdmins.length > 0) {
                await connection.end();
                return {
                    statusCode: 200,
                    headers,
                    body: JSON.stringify({ success: true, role: 'super_admin', message: 'Welcome Super Admin' })
                };
            }

            // 2. Check Mapping for Shop User
            const [mapping] = await connection.execute(
                'SELECT db_name FROM salespro_central_admin.user_to_shop_mapping WHERE email = ?',
                [email]
            );

            if (mapping.length > 0) {
                const shopDbName = mapping[0].db_name;
                const [users] = await connection.execute(
                    `SELECT * FROM ${shopDbName}.user_role_table WHERE email = ? AND password = ?`,
                    [email, hashPassword(password)]
                );

                if (users.length > 0) {
                    await connection.end();
                    return {
                        statusCode: 200,
                        headers,
                        body: JSON.stringify({
                            success: true,
                            role: 'shop_user',
                            dbName: shopDbName,
                            userData: users[0], // Return full user record
                            message: 'Login successful'
                        })
                    };
                }
            }

            await connection.end();
            return { statusCode: 401, headers, body: JSON.stringify({ success: false, message: 'Invalid credentials' }) };
        }

        if (action === 'sync-sale') {
            const { dbName, saleData, itemsList } = body;
            console.log(`Syncing Sale ${saleData.sales_invoice_number} on ${dbName}`);

            if (!dbName) {
                if (connection) await connection.end();
                return { statusCode: 400, headers, body: JSON.stringify({ success: false, message: 'dbName required' }) };
            }

            await connection.query(`USE \`${dbName}\``);
            try {
                // 1. Schema Pre-check & Auto-patch (Outside Transaction)
                // We do a "Dry Run" by trying to execute a dummy INSERT or simply by letting the transaction fail and retry outside.
                // A better way is to attempt the logic once, and if it fails due to missing column, patch and retry.
                let synced = false;
                let retries = 5;
                while (!synced && retries > 0) {
                    try {
                        await connection.beginTransaction();

                        // 1. Check if sale already exists
                        const [existingRows] = await connection.execute('SELECT `is_deleted`, `due_amount`, `customer_phone` FROM `sales_table` WHERE `sales_invoice_number` = ?', [saleData.sales_invoice_number]);
                        const exists = existingRows.length > 0;
                        const wasDeleted = exists && (existingRows[0].is_deleted == 1 || existingRows[0].is_deleted === true);
                        const isNewSale = !exists;

                        // 2. Prepare Sales Table Upsert
                        const saleCols = Object.keys(saleData).map(k => `\`${k}\``).join(', ');
                        const saleVals = Object.values(saleData);
                        const salePlaceholders = saleVals.map(() => '?').join(', ');
                        const saleUpdate = Object.keys(saleData).map(k => `\`${k}\` = VALUES(\`${k}\`)`).join(', ');

                        const saleSql = `INSERT INTO \`sales_table\` (${saleCols}) VALUES (${salePlaceholders}) ON DUPLICATE KEY UPDATE ${saleUpdate}`;
                        await connection.execute(saleSql, saleVals);

                        // 3. Update Customer Balance
                        if (isNewSale && !saleData.is_deleted && (saleData.due_amount || 0) > 0 && saleData.customer_phone) {
                            await connection.execute(
                                'UPDATE `customer_table` SET `due_amount` = `due_amount` + ? WHERE `phone_number` = ?',
                                [saleData.due_amount, saleData.customer_phone]
                            );
                        } else if (exists && !wasDeleted && saleData.is_deleted && (existingRows[0].due_amount || 0) > 0 && existingRows[0].customer_phone) {
                            await connection.execute(
                                'UPDATE `customer_table` SET `due_amount` = `due_amount` - ? WHERE `phone_number` = ?',
                                [existingRows[0].due_amount, existingRows[0].customer_phone]
                            );
                        }

                        // 3. Clear and Re-insert Items for this invoice
                        await connection.execute('DELETE FROM `sale_items_table` WHERE `invoice_number` = ?', [saleData.sales_invoice_number]);

                        for (const item of itemsList) {
                            const itemCols = Object.keys(item).map(k => `\`${k}\``).join(', ');
                            const itemVals = Object.values(item);
                            const itemPlaceholders = itemVals.map(() => '?').join(', ');
                            const itemSql = `INSERT INTO \`sale_items_table\` (${itemCols}) VALUES (${itemPlaceholders})`;
                            await connection.execute(itemSql, itemVals);

                            // 4. Update Stock in products_table if it's a new sale
                            if (isNewSale && item.product_code) {
                                await connection.execute(
                                    'UPDATE `products_table` SET `product_stock` = CAST(`product_stock` AS SIGNED) - ? WHERE `product_code` = ?',
                                    [item.quantity || 0, item.product_code]
                                );
                            }
                        }

                        // 5. Decrease Subscription Sale Limit
                        if (isNewSale && !saleData.is_deleted) {
                            await connection.execute(
                                'UPDATE `subscription_table` SET `sale_number` = `sale_number` - 1 WHERE `sale_number` > 0'
                            );
                        }

                        await connection.commit();
                        synced = true;
                    } catch (syncErr) {
                        await connection.rollback();
                        if (syncErr.code === 'ER_BAD_FIELD_ERROR' && retries > 1) {
                            const match = syncErr.message.match(/Unknown column '(.+?)' in/);
                            if (match) {
                                const missingCol = match[1];
                                console.log(`[Auto-Patch] Adding missing column '${missingCol}' outside transaction...`);
                                try { await connection.execute(`ALTER TABLE \`sales_table\` ADD COLUMN \`${missingCol}\` LONGTEXT`); } catch (e) { }
                                try { await connection.execute(`ALTER TABLE \`sale_items_table\` ADD COLUMN \`${missingCol}\` LONGTEXT`); } catch (e) { }
                                retries--;
                                continue;
                            }
                        }
                        throw syncErr;
                    }
                }

                await connection.end();
                return {
                    statusCode: 200,
                    headers,
                    body: JSON.stringify({ success: true, message: 'Sale synced successfully' })
                };
            } catch (err) {
                await connection.rollback();
                console.error("Sync Transaction Error:", err);
                if (connection) await connection.end();
                return {
                    statusCode: 500,
                    headers,
                    body: JSON.stringify({ success: false, message: err.message, code: err.code })
                };
            }
        }

        if (action === 'sync-purchase') {
            const { dbName, purchaseData, itemsList } = body;
            console.log(`Syncing Purchase ${purchaseData.invoice_number} on ${dbName}`);

            if (!dbName) {
                if (connection) await connection.end();
                return { statusCode: 400, headers, body: JSON.stringify({ success: false, message: 'dbName required' }) };
            }

            await connection.query(`USE \`${dbName}\``);
            try {
                let synced = false;
                let retries = 5;
                while (!synced && retries > 0) {
                    try {
                        // 1. Check if purchase already exists
                        const [existingRows] = await connection.execute('SELECT `is_deleted`, `due_amount`, `customer_phone` FROM `purchase_table` WHERE `invoice_number` = ?', [purchaseData.invoice_number]);
                        const exists = existingRows.length > 0;
                        const wasDeleted = exists && (existingRows[0].is_deleted == 1 || existingRows[0].is_deleted === true);
                        const isNewPurchase = !exists;

                        const purchaseCols = Object.keys(purchaseData).map(k => `\`${k}\``).join(', ');
                        const purchaseVals = Object.values(purchaseData);
                        const purchasePlaceholders = purchaseVals.map(() => '?').join(', ');
                        const purchaseUpdate = Object.keys(purchaseData).map(k => `\`${k}\` = VALUES(\`${k}\`)`).join(', ');

                        const purchaseSql = `INSERT INTO \`purchase_table\` (${purchaseCols}) VALUES (${purchasePlaceholders}) ON DUPLICATE KEY UPDATE ${purchaseUpdate}`;
                        await connection.execute(purchaseSql, purchaseVals);

                        // 2. Update Supplier Balance
                        if (isNewPurchase && !purchaseData.is_deleted && (purchaseData.due_amount || 0) > 0 && purchaseData.customer_phone) {
                            await connection.execute(
                                'UPDATE `customer_table` SET `due_amount` = `due_amount` + ? WHERE `phone_number` = ?',
                                [purchaseData.due_amount, purchaseData.customer_phone]
                            );
                        } else if (exists && !wasDeleted && purchaseData.is_deleted && (existingRows[0].due_amount || 0) > 0 && existingRows[0].customer_phone) {
                            await connection.execute(
                                'UPDATE `customer_table` SET `due_amount` = `due_amount` - ? WHERE `phone_number` = ?',
                                [existingRows[0].due_amount, existingRows[0].customer_phone]
                            );
                        }

                        await connection.execute('DELETE FROM `purchase_items_table` WHERE `invoice_number` = ?', [purchaseData.invoice_number]);

                        for (const item of itemsList) {
                            const itemCols = Object.keys(item).map(k => `\`${k}\``).join(', ');
                            const itemVals = Object.values(item);
                            const itemPlaceholders = itemVals.map(() => '?').join(', ');
                            const itemSql = `INSERT INTO \`purchase_items_table\` (${itemCols}) VALUES (${itemPlaceholders})`;
                            await connection.execute(itemSql, itemVals);

                            // Update Stock in products_table if it's a new purchase
                            if (isNewPurchase && item.product_code) {
                                await connection.execute(
                                    'UPDATE `products_table` SET `product_stock` = CAST(`product_stock` AS SIGNED) + ? WHERE `product_code` = ?',
                                    [item.quantity || 0, item.product_code]
                                );
                            }
                        }

                        // 3. Decrease Subscription Purchase Limit
                        if (isNewPurchase && !purchaseData.is_deleted) {
                            await connection.execute(
                                'UPDATE `subscription_table` SET `purchase_number` = `purchase_number` - 1 WHERE `purchase_number` > 0'
                            );
                        }

                        await connection.commit();
                        synced = true;
                    } catch (syncErr) {
                        await connection.rollback();
                        if (syncErr.code === 'ER_BAD_FIELD_ERROR' && retries > 1) {
                            const match = syncErr.message.match(/Unknown column '(.+?)' in/);
                            if (match) {
                                const missingCol = match[1];
                                console.log(`[Auto-Patch] Adding missing column '${missingCol}' outside transaction...`);
                                try { await connection.execute(`ALTER TABLE \`purchase_table\` ADD COLUMN \`${missingCol}\` LONGTEXT`); } catch (e) { }
                                try { await connection.execute(`ALTER TABLE \`purchase_items_table\` ADD COLUMN \`${missingCol}\` LONGTEXT`); } catch (e) { }
                                retries--;
                                continue;
                            }
                        }
                        throw syncErr;
                    }
                }

                await connection.end();
                return {
                    statusCode: 200,
                    headers,
                    body: JSON.stringify({ success: true, message: 'Purchase synced successfully' })
                };
            } catch (err) {
                await connection.rollback();
                console.error("Sync Purchase Error:", err);
                if (connection) await connection.end();
                return {
                    statusCode: 500,
                    headers,
                    body: JSON.stringify({ success: false, message: err.message, code: err.code })
                };
            }
        }

        if (action === 'sync-purchase-return') {
            const { dbName, returnData, itemsList } = body;
            console.log(`Syncing Purchase Return ${returnData.invoice_number} on ${dbName}`);

            if (!dbName) {
                if (connection) await connection.end();
                return { statusCode: 400, headers, body: JSON.stringify({ success: false, message: 'dbName required' }) };
            }

            await connection.query(`USE \`${dbName}\``);
            try {
                let synced = false;
                let retries = 5;
                while (!synced && retries > 0) {
                    try {
                        await connection.beginTransaction();

                        const returnCols = Object.keys(returnData).map(k => `\`${k}\``).join(', ');
                        const returnVals = Object.values(returnData);
                        const returnPlaceholders = returnVals.map(() => '?').join(', ');
                        const returnUpdate = Object.keys(returnData).map(k => `\`${k}\` = VALUES(\`${k}\`)`).join(', ');

                        const returnSql = `INSERT INTO \`purchase_return_table\` (${returnCols}) VALUES (${returnPlaceholders}) ON DUPLICATE KEY UPDATE ${returnUpdate}`;
                        await connection.execute(returnSql, returnVals);

                        await connection.execute('DELETE FROM `purchase_return_items_table` WHERE `invoice_number` = ?', [returnData.invoice_number]);

                        for (const item of itemsList) {
                            const itemCols = Object.keys(item).map(k => `\`${k}\``).join(', ');
                            const itemVals = Object.values(item);
                            const itemPlaceholders = itemVals.map(() => '?').join(', ');
                            const itemSql = `INSERT INTO \`purchase_return_items_table\` (${itemCols}) VALUES (${itemPlaceholders})`;
                            await connection.execute(itemSql, itemVals);

                            // Update Stock in products_table (Return increases stock)
                            if (item.product_code) {
                                await connection.execute(
                                    'UPDATE `products_table` SET `product_stock` = CAST(`product_stock` AS SIGNED) + ? WHERE `product_code` = ?',
                                    [item.quantity || 0, item.product_code]
                                );
                            }
                        }

                        await connection.commit();
                        synced = true;
                    } catch (syncErr) {
                        await connection.rollback();
                        if (syncErr.code === 'ER_BAD_FIELD_ERROR' && retries > 1) {
                            const match = syncErr.message.match(/Unknown column '(.+?)' in/);
                            if (match) {
                                const missingCol = match[1];
                                console.log(`[Auto-Patch] Adding missing column '${missingCol}' outside transaction...`);
                                try { await connection.execute(`ALTER TABLE \`purchase_return_table\` ADD COLUMN \`${missingCol}\` LONGTEXT`); } catch (e) { }
                                try { await connection.execute(`ALTER TABLE \`purchase_return_items_table\` ADD COLUMN \`${missingCol}\` LONGTEXT`); } catch (e) { }
                                retries--;
                                continue;
                            }
                        }
                        throw syncErr;
                    }
                }

                await connection.end();
                return {
                    statusCode: 200,
                    headers,
                    body: JSON.stringify({ success: true, message: 'Purchase Return synced successfully' })
                };
            } catch (err) {
                await connection.rollback();
                console.error("Sync Purchase Return Error:", err);
                if (connection) await connection.end();
                return {
                    statusCode: 500,
                    headers,
                    body: JSON.stringify({ success: false, message: err.message, code: err.code })
                };
            }
        }

        if (action === 'sync-due-transaction') {
            const { dbName, transactionData } = body;
            console.log(`Syncing Due Transaction ${transactionData.invoice_number} on ${dbName}`);

            if (!dbName) {
                if (connection) await connection.end();
                return { statusCode: 400, headers, body: JSON.stringify({ success: false, message: 'dbName required' }) };
            }

            await connection.query(`USE \`${dbName}\``);

            try {
                let synced = false;
                let retries = 5;
                while (!synced && retries > 0) {
                    try {
                        await connection.beginTransaction();

                        // 1. Check if transaction already exists to avoid double adjustment
                        // Unique check using (invoice_number, purchase_date, pay_due_amount)
                        const [existing] = await connection.execute(
                            'SELECT 1 FROM `due_transaction_table` WHERE `invoice_number` = ? AND `purchase_date` = ? AND `pay_due_amount` = ?',
                            [transactionData.invoice_number, transactionData.purchase_date, transactionData.pay_due_amount]
                        );
                        const isNewTransaction = existing.length === 0;

                        // 2. Insert/Update Due Transaction record explicit logic
                        const cols = Object.keys(transactionData).map(k => `\`${k}\``).join(', ');
                        const vals = Object.values(transactionData);
                        const placeholders = vals.map(() => '?').join(', ');

                        if (isNewTransaction) {
                            const sql = `INSERT INTO \`due_transaction_table\` (${cols}) VALUES (${placeholders})`;
                            await connection.execute(sql, vals);
                        } else {
                            const updateStmt = Object.keys(transactionData).map(k => `\`${k}\` = ?`).join(', ');
                            const sql = `UPDATE \`due_transaction_table\` SET ${updateStmt} WHERE \`invoice_number\` = ? AND \`purchase_date\` = ? AND \`pay_due_amount\` = ?`;
                            await connection.execute(sql, [...vals, transactionData.invoice_number, transactionData.purchase_date, transactionData.pay_due_amount]);
                        }

                        // 3. Atomically update related balances if it's a new record
                        if (isNewTransaction) {
                            const payAmount = parseFloat(transactionData.pay_due_amount) || 0;
                            const phone = transactionData.customer_phone;
                            const inv = transactionData.invoice_number;
                            const type = transactionData.customer_type;

                            // Update Customer/Supplier total due balance
                            await connection.execute(
                                'UPDATE `customer_table` SET `due_amount` = `due_amount` - ? WHERE `phone_number` = ?',
                                [payAmount, phone]
                            );

                            // Update specific Sale or Purchase due balance
                            if (type === 'Supplier') {
                                await connection.execute(
                                    'UPDATE `purchase_table` SET `due_amount` = `due_amount` - ? WHERE `invoice_number` = ?',
                                    [payAmount, inv]
                                );
                            } else {
                                await connection.execute(
                                    'UPDATE `sales_table` SET `due_amount` = `due_amount` - ? WHERE `sales_invoice_number` = ?',
                                    [payAmount, inv]
                                );
                            }

                            // 4. Decrease Subscription Due Limit
                            await connection.execute(
                                'UPDATE `subscription_table` SET `due_number` = `due_number` - 1 WHERE `due_number` > 0'
                            );
                        }

                        await connection.commit();
                        synced = true;
                    } catch (syncErr) {
                        await connection.rollback();
                        if (syncErr.code === 'ER_BAD_FIELD_ERROR' && retries > 1) {
                            const match = syncErr.message.match(/Unknown column '(.+?)' in/);
                            if (match) {
                                const missingCol = match[1];
                                try { await connection.execute(`ALTER TABLE \`due_transaction_table\` ADD COLUMN \`${missingCol}\` LONGTEXT`); } catch (e) { }
                                retries--;
                                continue;
                            }
                        }
                        if (syncErr.code === 'ER_NO_SUCH_TABLE' && retries > 1) {
                            const tableSchemas = schema(dbName);
                            const createQuery = tableSchemas.find(s => s.includes(`due_transaction_table`));
                            if (createQuery) {
                                await connection.execute(createQuery);
                                retries--;
                                continue;
                            }
                        }
                        throw syncErr;
                    }
                }

                await connection.end();
                return {
                    statusCode: 200,
                    headers,
                    body: JSON.stringify({ success: true, message: 'Due transaction synced successfully' })
                };
            } catch (err) {
                console.error("Sync Due Transaction Error:", err);
                if (connection) await connection.end();
                return {
                    statusCode: 500,
                    headers,
                    body: JSON.stringify({ success: false, message: err.message, code: err.code })
                };
            }
        }

        if (action === 'sync-product') {
            const { dbName, productData } = body;
            if (!dbName) {
                if (connection) await connection.end();
                return { statusCode: 400, headers, body: JSON.stringify({ success: false, message: 'dbName required' }) };
            }
            await connection.query(`USE \`${dbName}\``);
            try {
                // --- CRITICAL FIX: Never overwrite cloud image with empty string ---
                // If product_picture is empty/null/short, remove it from the upsert
                // so the existing cloud image is preserved on UPDATE
                const safeData = { ...productData };
                const pic = safeData.product_picture;
                const hasPicture = pic && typeof pic === 'string' && pic.trim().length > 100;
                if (!hasPicture) {
                    delete safeData.product_picture;
                }

                // Always stamp updated_at so incremental pull sync can detect changes
                safeData.updated_at = new Date().toISOString().slice(0, 19).replace('T', ' ');

                let synced = false;
                let retries = 5;
                while (!synced && retries > 0) {
                    try {
                        const cols = Object.keys(safeData).map(k => `\`${k}\``).join(', ');
                        const vals = Object.values(safeData);
                        const placeholders = vals.map(() => '?').join(', ');
                        // On duplicate: update all fields EXCEPT product_picture if it's not in safeData
                        const updateKeys = Object.keys(safeData).filter(k => k !== 'product_code');
                        const update = updateKeys.map(k => `\`${k}\` = VALUES(\`${k}\`)`).join(', ');

                        const [existing] = await connection.execute(
                            'SELECT 1 FROM `products_table` WHERE `product_code` = ?',
                            [safeData.product_code]
                        );
                        const isNew = existing.length === 0;

                        await connection.execute(
                            `INSERT INTO \`products_table\` (${cols}) VALUES (${placeholders}) ON DUPLICATE KEY UPDATE ${update}`,
                            vals
                        );

                        if (isNew && !safeData.is_deleted) {
                            await connection.execute(
                                'UPDATE `subscription_table` SET `products` = `products` - 1 WHERE `products` > 0'
                            );
                        }
                        synced = true;
                    } catch (syncErr) {
                        if (syncErr.code === 'ER_DATA_TOO_LONG' && retries > 1) {
                            console.log(`[Auto-Patch] Upgrading products_table.product_picture to LONGTEXT...`);
                            try { await connection.execute(`ALTER TABLE \`products_table\` MODIFY COLUMN \`product_picture\` LONGTEXT`); } catch(e) {}
                            retries--;
                            continue;
                        }
                        if (syncErr.code === 'ER_BAD_FIELD_ERROR' && retries > 1) {
                            const match = syncErr.message.match(/Unknown column '(.+?)' in/);
                            if (match) {
                                const missingCol = match[1];
                                console.log(`[Auto-Patch] Adding missing column '${missingCol}' to products_table...`);
                                try { await connection.execute(`ALTER TABLE \`products_table\` ADD COLUMN \`${missingCol}\` LONGTEXT`); } catch(e) {}
                                retries--;
                                continue;
                            }
                        }
                        throw syncErr;
                    }
                }

                if (connection) await connection.end();
                return { statusCode: 200, headers, body: JSON.stringify({ success: true }) };
            } catch (err) {
                console.error('sync-product error:', err.message);
                if (connection) await connection.end();
                return { statusCode: 500, headers, body: JSON.stringify({ success: false, message: err.message }) };
            }
        }

        if (action === 'sync-customer') {
            const { dbName, customerData } = body;
            await connection.query(`USE \`${dbName}\``);
            try {
                const cols = Object.keys(customerData).map(k => `\`${k}\``).join(', ');
                const vals = Object.values(customerData);
                const placeholders = vals.map(() => '?').join(', ');
                const update = Object.keys(customerData).map(k => `\`${k}\` = VALUES(\`${k}\`)`).join(', ');

                const [existing] = await connection.execute('SELECT 1 FROM `customer_table` WHERE `phone_number` = ?', [customerData.phone_number]);
                const isNew = existing.length === 0;

                await connection.execute(`INSERT INTO \`customer_table\` (${cols}) VALUES (${placeholders}) ON DUPLICATE KEY UPDATE ${update}`, vals);
                if (isNew && !customerData.is_deleted) {
                    await connection.execute('UPDATE `subscription_table` SET `parties_number` = `parties_number` - 1 WHERE `parties_number` > 0');
                }
                if (connection) await connection.end();
                return { statusCode: 200, headers, body: JSON.stringify({ success: true }) };
            } catch (err) {
                if (err.code === 'ER_DATA_TOO_LONG') {
                    console.log(`[Auto-Patch] Upgrading customer_table.profile_picture to LONGTEXT due to data length...`);
                    await connection.execute(`ALTER TABLE \`${dbName}\`.customer_table MODIFY COLUMN \`profile_picture\` LONGTEXT`);
                    await connection.execute(`INSERT INTO \`customer_table\` (${cols}) VALUES (${placeholders}) ON DUPLICATE KEY UPDATE ${update}`, vals);
                    if (connection) await connection.end();
                    return { statusCode: 200, headers, body: JSON.stringify({ success: true }) };
                }
                if (connection) await connection.end();
                return { statusCode: 500, headers, body: JSON.stringify({ success: false, message: err.message }) };
            }
        }

        // --- DELETE PRODUCT ACTION ---
        if (action === 'delete-product') {
            const { dbName, productCode } = body;
            console.log(`Deleting product ${productCode} from ${dbName}`);

            if (!dbName) {
                if (connection) await connection.end();
                return { statusCode: 400, headers, body: JSON.stringify({ success: false, message: 'dbName required' }) };
            }

            const [result] = await connection.execute(`UPDATE \`${dbName}\`.products_table SET is_deleted = 1, updated_at = NOW() WHERE product_code = ?`, [productCode]);
            const affectedRows = result.affectedRows;

            if (connection) await connection.end();
            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({ success: affectedRows > 0, affectedRows: affectedRows, message: affectedRows > 0 ? 'Product deleted successfully' : 'Product not found or already deleted' })
            };
        }

        // --- DATA QUERY ACTION (For Web POS) ---
        if (action === 'query') {
            let { dbName, sql, args } = body;
            console.log(`Original SQL on ${dbName}: ${sql}`);

            // Basic protection: Ensure dbName is provided
            if (!dbName || dbName.includes(';') || dbName.includes(' ')) {
                if (connection) await connection.end();
                return { statusCode: 400, headers, body: JSON.stringify({ success: false, message: 'Invalid DB Name' }) };
            }

            // Convert SQLite identity quotes (") to MySQL backticks (`)
            // Drift often quotes table and column names with double quotes.
            let convertedSql = sql.replace(/"/g, '`');

            // Fix SQLite-specific UPSERT syntaxes
            convertedSql = convertedSql.replace(/INSERT OR REPLACE INTO/gi, 'REPLACE INTO');
            convertedSql = convertedSql.replace(/INSERT OR IGNORE INTO/gi, 'INSERT IGNORE INTO');

            console.log(`Converted SQL: ${convertedSql}`);

            // Switch to the correct shop database
            await connection.query(`USE \`${dbName}\``);

            // Execute the query with a self-healing schema loop for missing columns
            let maxRetries = 15;
            while (maxRetries > 0) {
                try {
                    // Use .query instead of .execute for the general query action to be more flexible with types
                    const [result] = await connection.query(convertedSql, args || []);
                    console.log(`Query Successful. Returned ${Array.isArray(result) ? result.length : 'non-array'} results.`);

                    if (connection) await connection.end();
                    const finalData = Array.isArray(result) ? result : [result];
                    return {
                        statusCode: 200,
                        headers,
                        body: JSON.stringify({
                            success: true,
                            data: finalData,
                            insertId: result.insertId,
                            affectedRows: result.affectedRows
                        }, (key, value) => (typeof value === 'bigint' ? value.toString() : value))
                    };
                } catch (queryErr) {
                    if (queryErr.code === 'ER_BAD_FIELD_ERROR') {
                        const match = queryErr.message.match(/Unknown column '(.+?)' in/);
                        let tableNameMatch = convertedSql.match(/INTO\s+`?([a-zA-Z0-9_]+)`?/i);
                        if (!tableNameMatch) tableNameMatch = convertedSql.match(/UPDATE\s+`?([a-zA-Z0-9_]+)`?/i);
                        if (!tableNameMatch) tableNameMatch = convertedSql.match(/FROM\s+`?([a-zA-Z0-9_]+)`?/i);

                        if (match && tableNameMatch) {
                            const missingCol = match[1];
                            const tableName = tableNameMatch[1];
                            console.log(`[Auto-Patch] Adding missing column '${missingCol}' to ${tableName} on ${dbName}...`);

                            let columnType = 'LONGTEXT';
                            if (missingCol === 'is_synced' || missingCol === 'is_paid' || missingCol.startsWith('show_') || missingCol === 'auto_print' || missingCol.startsWith('is_')) {
                                columnType = 'BOOLEAN DEFAULT FALSE';
                            } else if (missingCol.includes('amount') || missingCol.includes('price') || missingCol.includes('point') || missingCol === 'vat' || missingCol === 'loss_profit') {
                                columnType = 'DOUBLE DEFAULT 0';
                            }

                            await connection.execute(`ALTER TABLE \`${dbName}\`.\`${tableName}\` ADD COLUMN \`${missingCol}\` ${columnType}`);
                            maxRetries--;
                            continue; // Retry immediately after adding the column
                        }
                    }

                    if (queryErr.code === 'ER_NO_SUCH_TABLE') {
                        let tableNameMatch = convertedSql.match(/INTO\s+`?([a-zA-Z0-9_]+)`?/i);
                        if (!tableNameMatch) tableNameMatch = convertedSql.match(/UPDATE\s+`?([a-zA-Z0-9_]+)`?/i);
                        if (!tableNameMatch) tableNameMatch = convertedSql.match(/FROM\s+`?([a-zA-Z0-9_]+)`?/i);

                        if (tableNameMatch) {
                            const tableName = tableNameMatch[1];
                            console.log(`[Auto-Patch] Table '${tableName}' missing on ${dbName}. Attempting to create...`);
                            const tableSchemas = schema(dbName);
                            const createQuery = tableSchemas.find(s => s.includes(`.${tableName} `) || s.includes(`.\`${tableName}\` `));
                            if (createQuery) {
                                await connection.execute(createQuery);
                                maxRetries--;
                                continue;
                            }
                        }
                    }

                    // --- ER_DATA_TOO_LONG HANDLING ---
                    if (queryErr.code === 'ER_DATA_TOO_LONG' || queryErr.errno === 1406) {
                        const match = queryErr.message.match(/column '(.+?)'/);
                        let tableNameMatch = convertedSql.match(/INTO\s+`?([a-zA-Z0-9_]+)`?/i);
                        if (!tableNameMatch) tableNameMatch = convertedSql.match(/UPDATE\s+`?([a-zA-Z0-9_]+)`?/i);
                        if (!tableNameMatch) tableNameMatch = convertedSql.match(/REPLACE INTO\s+`?([a-zA-Z0-9_]+)`?/i);

                        if (match && tableNameMatch) {
                            const tooSmallCol = match[1];
                            const tableName = tableNameMatch[1];
                            console.log(`[Auto-Patch] Upgrading column '${tooSmallCol}' in ${tableName} on ${dbName} to LONGTEXT due to data length...`);
                            await connection.execute(`ALTER TABLE \`${dbName}\`.\`${tableName}\` MODIFY COLUMN \`${tooSmallCol}\` LONGTEXT`);
                            maxRetries--;
                            continue; // Retry original query
                        }
                    }
                    if (connection) await connection.end();

                    // Return failure cleanly so proxy can handle it if not an auto-patchable error
                    return {
                        statusCode: 500,
                        headers,
                        body: JSON.stringify({
                            success: false,
                            message: queryErr.message
                        })
                    };
                }
            }
            if (connection) await connection.end();
            return {
                statusCode: 500,
                headers,
                body: JSON.stringify({
                    success: false,
                    message: "Exceeded maximum schema auto-patching retries."
                })
            };
        }

        // --- REGISTER USER IN CENTRAL MAPPING ---
        if (action === 'register-user') {
            const { userEmail, shopDbName } = body;
            await connection.execute(
                'INSERT IGNORE INTO salespro_central_admin.user_to_shop_mapping (email, db_name) VALUES (?, ?)',
                [userEmail, shopDbName]
            );
            await connection.end();
            return { statusCode: 200, headers, body: JSON.stringify({ success: true, message: 'User mapping updated' }) };
        }

        // --- CHECK EMAIL AVAILABILITY ---
        if (action === 'is-email-available') {
            const { email } = body;
            const [rows] = await connection.execute(
                'SELECT email FROM salespro_central_admin.user_to_shop_mapping WHERE email = ?',
                [email]
            );
            await connection.end();
            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({
                    success: true,
                    available: rows.length === 0,
                    message: rows.length === 0 ? 'Email is available' : 'Email already in use'
                })
            };
        }

        // --- GLOBAL SUBSCRIPTION PLANS CRUD ---
        if (action === 'get-global-plans') {
            await connection.execute(`CREATE TABLE IF NOT EXISTS salespro_central_admin.subscription_plans_global (
                subscriptionName VARCHAR(100) PRIMARY KEY,
                duration INT NOT NULL,
                subscriptionPrice INT NOT NULL,
                offerPrice INT NOT NULL,
                saleNumber INT NOT NULL,
                purchaseNumber INT NOT NULL,
                partiesNumber INT NOT NULL,
                dueNumber INT NOT NULL,
                products INT NOT NULL
            )`);
            const [plans] = await connection.execute(
                `SELECT * FROM salespro_central_admin.subscription_plans_global`
            );
            await connection.end();
            return { statusCode: 200, headers, body: JSON.stringify({ success: true, plans }) };
        }

        if (action === 'add-global-plan') {
            const p = body.plan;
            await connection.execute(`CREATE TABLE IF NOT EXISTS salespro_central_admin.subscription_plans_global (
                subscriptionName VARCHAR(100) PRIMARY KEY,
                duration INT NOT NULL,
                subscriptionPrice INT NOT NULL,
                offerPrice INT NOT NULL,
                saleNumber INT NOT NULL,
                purchaseNumber INT NOT NULL,
                partiesNumber INT NOT NULL,
                dueNumber INT NOT NULL,
                products INT NOT NULL
            )`);
            await connection.execute(
                `INSERT INTO salespro_central_admin.subscription_plans_global 
                 (subscriptionName, duration, subscriptionPrice, offerPrice, saleNumber, purchaseNumber, partiesNumber, dueNumber, products)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [p.subscriptionName, p.duration, p.subscriptionPrice, p.offerPrice, p.saleNumber, p.purchaseNumber, p.partiesNumber, p.dueNumber, p.products]
            );
            await connection.end();
            return { statusCode: 200, headers, body: JSON.stringify({ success: true }) };
        }

        if (action === 'update-global-plan') {
            const p = body.plan;
            await connection.execute(
                `UPDATE salespro_central_admin.subscription_plans_global SET 
                 duration = ?, subscriptionPrice = ?, offerPrice = ?, saleNumber = ?, purchaseNumber = ?, partiesNumber = ?, dueNumber = ?, products = ?
                 WHERE subscriptionName = ?`,
                [p.duration, p.subscriptionPrice, p.offerPrice, p.saleNumber, p.purchaseNumber, p.partiesNumber, p.dueNumber, p.products, p.subscriptionName]
            );
            await connection.end();
            return { statusCode: 200, headers, body: JSON.stringify({ success: true }) };
        }

        if (action === 'delete-global-plan') {
            await connection.execute(
                `DELETE FROM salespro_central_admin.subscription_plans_global WHERE subscriptionName = ?`,
                [body.subscriptionName]
            );
            await connection.end();
            return { statusCode: 200, headers, body: JSON.stringify({ success: true }) };
        }

        // --- GLOBAL CURRENCIES CRUD ---
        if (action === 'get-global-currencies') {
            await connection.execute(`CREATE TABLE IF NOT EXISTS salespro_central_admin.currencies_global (
                name VARCHAR(100) PRIMARY KEY,
                symbol VARCHAR(20) NOT NULL
            )`);
            const [currencies] = await connection.execute(
                `SELECT * FROM salespro_central_admin.currencies_global`
            );
            await connection.end();
            return { statusCode: 200, headers, body: JSON.stringify({ success: true, currencies }) };
        }

        if (action === 'add-global-currency') {
            const { name, symbol } = body;
            await connection.execute(`CREATE TABLE IF NOT EXISTS salespro_central_admin.currencies_global (
                name VARCHAR(100) PRIMARY KEY,
                symbol VARCHAR(20) NOT NULL
            )`);
            await connection.execute(
                `INSERT INTO salespro_central_admin.currencies_global (name, symbol) VALUES (?, ?)`,
                [name, symbol]
            );
            await connection.end();
            return { statusCode: 200, headers, body: JSON.stringify({ success: true, message: 'Global currency added' }) };
        }

        if (action === 'delete-global-currency') {
            const { name } = body;
            await connection.execute(
                `DELETE FROM salespro_central_admin.currencies_global WHERE name = ?`,
                [name]
            );
            await connection.end();
            return { statusCode: 200, headers, body: JSON.stringify({ success: true, message: 'Global currency deleted' }) };
        }

        // --- GET ALL SHOPS WITH SUBSCRIPTION STATUS ---
        if (action === 'get-shops') {
            console.log('Getting all shops from shops_directory...');

            // [FIX] Create salespro_central_admin DB first, then auto-create its tables
            await connection.execute(`CREATE DATABASE IF NOT EXISTS salespro_central_admin`);
            await connection.execute(`
                CREATE TABLE IF NOT EXISTS salespro_central_admin.shops_directory (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    shop_name TEXT NOT NULL,
                    db_name VARCHAR(255) UNIQUE NOT NULL,
                    admin_email TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
            await connection.execute(`
                CREATE TABLE IF NOT EXISTS salespro_central_admin.user_to_shop_mapping (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    db_name VARCHAR(255) NOT NULL
                )
            `);

            const [shops] = await connection.execute(
                `SELECT shop_name, db_name, admin_email FROM salespro_central_admin.shops_directory`
            );
            console.log(`Found ${shops.length} shops`);

            // For each shop, try to fetch subscription info
            const results = [];
            for (const shop of shops) {
                let subName = 'No Subscription';
                let expireDate = null;
                try {
                    const [subs] = await connection.execute(
                        `SELECT subscription_name, expire_date FROM \`${shop.db_name}\`.subscription_table LIMIT 1`
                    );
                    if (subs.length > 0) {
                        subName = subs[0].subscription_name || 'No Subscription';
                        expireDate = subs[0].expire_date || null;
                    }
                } catch (subErr) {
                    console.log(`No subscription table for ${shop.db_name}: ${subErr.message}`);
                }
                results.push({
                    shop_name: shop.shop_name,
                    db_name: shop.db_name,
                    admin_email: shop.admin_email,
                    subscription_name: subName,
                    expire_date: expireDate,
                });
            }
            await connection.end();
            console.log(`Returning ${results.length} shop results`);
            return { statusCode: 200, headers, body: JSON.stringify({ success: true, shops: results }) };
        }

        // --- SET SUBSCRIPTION FOR A SHOP ---
        if (action === 'set-subscription') {
            const { shopDbName, subscriptionName, durationDays } = body;

            // First, get the plan details to get correct limits
            const [globalPlans] = await connection.execute(
                `SELECT * FROM salespro_central_admin.subscription_plans_global WHERE subscriptionName = ?`,
                [subscriptionName]
            );

            let saleNumber = -202, purchaseNumber = -202, products = -202, partiesNumber = -202, dueNumber = -202;
            if (globalPlans.length > 0) {
                const plan = globalPlans[0];
                saleNumber = plan.saleNumber ?? -202;
                purchaseNumber = plan.purchaseNumber ?? -202;
                products = plan.products ?? -202;
                partiesNumber = plan.partiesNumber ?? -202;
                dueNumber = plan.dueNumber ?? -202;
            }

            const expireDate = new Date();
            expireDate.setDate(expireDate.getDate() + parseInt(durationDays));
            const expireDateStr = expireDate.toISOString().split('T')[0];
            const subscriptionDate = new Date().toISOString().split('T')[0];

            // Delete existing subscription and insert new one (clean upsert)
            await connection.execute(`DELETE FROM \`${shopDbName}\`.subscription_table WHERE 1=1`);
            await connection.execute(
                `INSERT INTO \`${shopDbName}\`.subscription_table 
                 (subscription_name, duration, subscription_date, expire_date, 
                  sale_number, purchase_number, products, parties_number, due_number,
                  total_sale_number, total_purchase_number, total_products, total_parties_number, total_due_number)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [subscriptionName, parseInt(durationDays), subscriptionDate, expireDateStr,
                    saleNumber, purchaseNumber, products, partiesNumber, dueNumber,
                    saleNumber, purchaseNumber, products, partiesNumber, dueNumber]
            );

            await connection.end();
            return {
                statusCode: 200, headers, body: JSON.stringify({
                    success: true,
                    expireDate: expireDateStr,
                    message: `Subscription '${subscriptionName}' set for ${durationDays} days`
                })
            };
        }

        // --- DELETE SHOP ACTION ---
        if (action === 'delete-shop') {
            const { dbName } = body;
            console.log(`DELETING SHOP DATABASE: ${dbName}`);

            // 1. Drop the specific shop database
            await connection.execute(`DROP DATABASE IF EXISTS \`${dbName}\``);

            // 2. Remove from global shops directory
            await connection.execute(
                'DELETE FROM salespro_central_admin.shops_directory WHERE db_name = ?',
                [dbName]
            );

            // 3. Remove all user mappings for this shop
            await connection.execute(
                'DELETE FROM salespro_central_admin.user_to_shop_mapping WHERE db_name = ?',
                [dbName]
            );

            await connection.end();
            return { statusCode: 200, headers, body: JSON.stringify({ success: true, message: `Shop ${dbName} deleted successfully` }) };
        }

        // --- REGISTER SHOP ACTION ---
        if (action === 'register') {
            const dbName = `shop_${shopName.toLowerCase().replace(/\s+/g, '_')}`;
            console.log("Registering Shop:", shopName, "| DB:", dbName);

            // [FIX 1] Create shop database with backticks
            await connection.execute(`CREATE DATABASE IF NOT EXISTS \`${dbName}\``);
            const queries = schema(dbName);
            for (const query of queries) {
                await connection.execute(query);
            }

            // [FIX 2] Create the salespro_central_admin DB first, THEN create its tables
            await connection.execute(`CREATE DATABASE IF NOT EXISTS salespro_central_admin`);
            await connection.execute(`
                CREATE TABLE IF NOT EXISTS salespro_central_admin.shops_directory (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    shop_name TEXT NOT NULL,
                    db_name VARCHAR(255) UNIQUE NOT NULL,
                    admin_email TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
            await connection.execute(`
                CREATE TABLE IF NOT EXISTS salespro_central_admin.user_to_shop_mapping (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    db_name VARCHAR(255) NOT NULL
                )
            `);

            // [FIX 3] INSERT IGNORE everywhere — safe on retries / duplicate emails
            await connection.execute(
                'INSERT IGNORE INTO salespro_central_admin.shops_directory (shop_name, db_name, admin_email) VALUES (?, ?, ?)',
                [shopName, dbName, adminEmail]
            );
            await connection.execute(
                'INSERT IGNORE INTO salespro_central_admin.user_to_shop_mapping (email, db_name) VALUES (?, ?)',
                [adminEmail, dbName]
            );

            await connection.execute(
                `INSERT IGNORE INTO \`${dbName}\`.personal_information_table (company_name, phone_number) VALUES (?, ?)`,
                [shopName, '']
            );

            await connection.execute(
                `INSERT IGNORE INTO \`${dbName}\`.user_role_table 
                 (email, password, user_title, database_id,
                  sale_permission, parties_permission, purchase_permission, product_permission,
                  profile_edit_permission, add_expense_permission, loss_profit_permission,
                  due_list_permission, stock_permission, reports_permission,
                  sales_list_permission, purchase_list_permission) 
                 VALUES (?, ?, ?, ?, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)`,
                [adminEmail, hashPassword(adminPassword), 'Admin', dbName]
            );

            // --- INITIALIZE RECEIPT SETTINGS ---
            await connection.execute(
                `INSERT IGNORE INTO \`${dbName}\`.receipt_settings_table 
                 (id, company_name, address, phone, logo_path, header_text, footer_text, layout_order) 
                 VALUES (1, ?, '', '', '', 'Welcome', 'Thank You', 'logo,name,address,phone,header,metadata,items,footer')`,
                [shopName]
            );

            await connection.execute(
                `INSERT IGNORE INTO \`${dbName}\`.business_settings_table (id, currency_name, currency_symbol, company_name) VALUES (1, 'Sri Lankan Rupee', 'LKR', ?)`,
                [shopName]
            );

            await connection.end();
            return { statusCode: 200, headers, body: JSON.stringify({ success: true, dbName, message: 'Shop registered successfully' }) };
        }

        // --- SYNC SCHEMA ACTION (Batch Migrations) ---
        if (action === 'sync-schema') {
            const { dbName, migrations } = body;
            console.log(`Syncing Schema for ${dbName}...`);

            if (!dbName) {
                if (connection) await connection.end();
                return { statusCode: 400, headers, body: JSON.stringify({ success: false, message: 'dbName required' }) };
            }

            const results = [];
            // 1. Get all existing columns for all relevant tables in one go
            const tablesToCheck = [...new Set(migrations.map(t => t.table))];
            const [existingColumns] = await connection.execute(
                `SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = ? AND table_name IN (${tablesToCheck.map(() => '?').join(', ')})`,
                [dbName, ...tablesToCheck]
            );

            const columnMap = {};
            existingColumns.forEach(row => {
                const tName = row.TABLE_NAME || row.table_name;
                const cName = row.COLUMN_NAME || row.column_name;
                if (tName && cName) {
                    const key = `${tName}.${cName}`.toLowerCase();
                    columnMap[key] = true;
                }
            });

            for (const item of migrations) {
                const { table, column, type } = item;
                const columnKey = `${table}.${column}`.toLowerCase();

                try {
                    // Check if table exists
                    const [tableCheck] = await connection.execute(
                        `SELECT 1 FROM information_schema.tables WHERE table_schema = ? AND table_name = ?`,
                        [dbName, table]
                    );

                    if (tableCheck.length === 0) {
                        console.log(`Table ${table} missing on ${dbName}. Creating...`);
                        const tableSchemas = schema(dbName);
                        const createQuery = tableSchemas.find(s => s.includes(`.${table} `) || s.includes(`.\`${table}\` `));
                        if (createQuery) {
                            await connection.execute(createQuery);
                            results.push({ table, status: 'table_created' });
                            continue;
                        }
                    }

                    // Only add if it doesn't exist
                    if (!columnMap[columnKey]) {
                        console.log(`Adding missing column ${column} to ${table}...`);
                        await connection.execute(`ALTER TABLE \`${dbName}\`.\`${table}\` ADD COLUMN \`${column}\` ${type}`);
                        results.push({ table, column, status: 'added' });
                    } else {
                        results.push({ table, column, status: 'exists' });
                    }
                } catch (e) {
                    results.push({ table, column, status: 'failed', error: e.message });
                }
            }

            if (connection) await connection.end();
            return { statusCode: 200, headers, body: JSON.stringify({ success: true, results }) };
        }

        // --- SYNC PROFILE DETAILS ---
        if (action === 'sync-profile') {
            const { dbName, businessSettings, personalInformation, receiptSettings } = body;
            console.log(`Syncing Profile for ${dbName}...`);

            if (!dbName) {
                if (connection) await connection.end();
                return { statusCode: 400, headers, body: JSON.stringify({ success: false, message: 'dbName required' }) };
            }

            await connection.query(`USE \`${dbName}\``);

            // 1. Push Business Settings
            if (businessSettings) {
                const cols = Object.keys(businessSettings).map(k => `\`${k}\``).join(', ');
                const vals = Object.values(businessSettings);
                const placeholders = vals.map(() => '?').join(', ');
                const update = Object.keys(businessSettings)
                    .filter(k => k !== 'id')
                    .map(k => `\`${k}\` = IF(VALUES(\`updated_at\`) > \`updated_at\` OR \`updated_at\` IS NULL, VALUES(\`${k}\`), \`${k}\`)`)
                    .join(', ');
                await connection.execute(`INSERT INTO \`business_settings_table\` (${cols}) VALUES (${placeholders}) ON DUPLICATE KEY UPDATE ${update}, \`updated_at\` = GREATEST(COALESCE(\`updated_at\`, '1970-01-01'), VALUES(\`updated_at\`))`, vals);
            }

            // 2. Push Personal Information
            if (personalInformation) {
                const cols = Object.keys(personalInformation).map(k => `\`${k}\``).join(', ');
                const vals = Object.values(personalInformation);
                const placeholders = vals.map(() => '?').join(', ');
                const update = Object.keys(personalInformation)
                    .filter(k => k !== 'id')
                    .map(k => `\`${k}\` = IF(VALUES(\`updated_at\`) > \`updated_at\` OR \`updated_at\` IS NULL, VALUES(\`${k}\`), \`${k}\`)`)
                    .join(', ');
                try {
                    await connection.execute(`INSERT INTO \`personal_information_table\` (${cols}) VALUES (${placeholders}) ON DUPLICATE KEY UPDATE ${update}, \`updated_at\` = GREATEST(COALESCE(\`updated_at\`, '1970-01-01'), VALUES(\`updated_at\`))`, vals);
                } catch (pErr) {
                    if (pErr.code === 'ER_DATA_TOO_LONG') {
                        console.log('[Auto-Patch] Altering personal_information_table columns to LONGTEXT due to data length...');
                        await connection.execute('ALTER TABLE `personal_information_table` MODIFY COLUMN `picture_url` LONGTEXT');
                        await connection.execute(`INSERT INTO \`personal_information_table\` (${cols}) VALUES (${placeholders}) ON DUPLICATE KEY UPDATE ${update}, \`updated_at\` = GREATEST(COALESCE(\`updated_at\`, '1970-01-01'), VALUES(\`updated_at\`))`, vals);
                    } else {
                        throw pErr;
                    }
                }
            }

            // 3. Push Receipt Settings
            if (receiptSettings) {
                const cols = Object.keys(receiptSettings).map(k => `\`${k}\``).join(', ');
                const vals = Object.values(receiptSettings);
                const placeholders = vals.map(() => '?').join(', ');
                const update = Object.keys(receiptSettings)
                    .filter(k => k !== 'id')
                    .map(k => `\`${k}\` = IF(VALUES(\`updated_at\`) > \`updated_at\` OR \`updated_at\` IS NULL, VALUES(\`${k}\`), \`${k}\`)`)
                    .join(', ');
                try {
                    await connection.execute(`INSERT INTO \`receipt_settings_table\` (${cols}) VALUES (${placeholders}) ON DUPLICATE KEY UPDATE ${update}, \`updated_at\` = GREATEST(COALESCE(\`updated_at\`, '1970-01-01'), VALUES(\`updated_at\`))`, vals);
                } catch (rErr) {
                    if (rErr.code === 'ER_DATA_TOO_LONG') {
                        console.log('[Auto-Patch] Altering logo_path to LONGTEXT due to Data Too Long error');
                        await connection.execute('ALTER TABLE `receipt_settings_table` MODIFY COLUMN `logo_path` LONGTEXT');
                        await connection.execute(`INSERT INTO \`receipt_settings_table\` (${cols}) VALUES (${placeholders}) ON DUPLICATE KEY UPDATE ${update}, \`updated_at\` = GREATEST(COALESCE(\`updated_at\`, '1970-01-01'), VALUES(\`updated_at\`))`, vals);
                    } else {
                        throw rErr;
                    }
                }
            }

            // 4. Pull Latest Data
            const [bRows] = await connection.execute('SELECT * FROM `business_settings_table` LIMIT 1');
            const [pRows] = await connection.execute('SELECT * FROM `personal_information_table` LIMIT 1');
            const [rRows] = await connection.execute('SELECT * FROM `receipt_settings_table` LIMIT 1');

            if (connection) await connection.end();
            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({
                    success: true,
                    businessSettings: bRows[0] || null,
                    personalInformation: pRows[0] || null,
                    receiptSettings: rRows[0] || null
                })
            };
        }
        // --- SECURE SUBSCRIPTION PULL ---
        if (action === 'pull-subscription') {
            const { dbName } = body;
            if (!dbName) {
                if (connection) await connection.end();
                return { statusCode: 400, headers, body: JSON.stringify({ success: false, message: 'dbName required' }) };
            }

            await connection.query(`USE \`${dbName}\``);
            const [rows] = await connection.execute('SELECT * FROM `subscription_table` LIMIT 1');
            
            if (rows.length > 0) {
                const subDataRaw = rows[0];
                const lastSyncedAt = new Date().toISOString();
                
                // CRITICAL: Stringify and parse to ensure we generate the HMAC on the EXACT string formats 
                // that the Flutter app will receive (e.g. converting MySQL Date objects to ISO strings).
                const subData = JSON.parse(JSON.stringify(subDataRaw));
                
                // HMAC Payload (dbName ensures it can't be copied between shops)
                const updatedAtStr = subData.updated_at ? new Date(subData.updated_at).toISOString() : '';
                const payloadToSign = `${dbName}|${subData.subscription_name}|${subData.sale_number}|${subData.purchase_number}|${subData.products}|${subData.parties_number}|${subData.due_number}|${subData.expire_date}|${lastSyncedAt}|${subData.duration}|${subData.subscription_date}|${subData.total_sale_number}|${subData.total_purchase_number}|${subData.total_products}|${subData.total_parties_number}|${subData.total_due_number}|${updatedAtStr}`;
                const SECRET = process.env.SUBSCRIPTION_SECRET || 'default_salespro_secret_key_123!';
                const signature = crypto.createHmac('sha256', SECRET).update(payloadToSign).digest('hex');
                
                if (connection) await connection.end();
                return {
                    statusCode: 200,
                    headers,
                    body: JSON.stringify({
                        success: true,
                        data: [{
                            ...subData,
                            // CRITICAL: Override updated_at with the EXACT ISO UTC string used during HMAC signing.
                            // MySQL returns datetime as '2026-06-25 06:46:03' (no timezone).
                            // Flutter running in non-UTC timezone (e.g. IST +5:30) would parse this as local time,
                            // causing a 5h30m offset mismatch in the HMAC payload.
                            // Sending the pre-computed ISO string ensures both sides use identical values.
                            updated_at: updatedAtStr,
                            signature: signature,
                            last_synced_at: lastSyncedAt
                        }]
                    })
                };
            } else {
                if (connection) await connection.end();
                return { statusCode: 200, headers, body: JSON.stringify({ success: true, data: [] }) };
            }
        }

        if (connection) await connection.end();
        return { statusCode: 400, headers, body: JSON.stringify({ success: false, message: 'Invalid action' }) };

    } catch (error) {
        console.error("FATAL ERROR:", error.message);
        if (connection) await connection.end();
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: error.message })
        };
    }
};

// Render (and local testing) Server Wrapper
if (require.main === module) {
    const express = require('express');
    const app = express();
    app.use(express.json());

    app.all('*', async (req, res) => {
        const event = {
            httpMethod: req.method,
            path: req.path,
            headers: req.headers,
            body: req.body ? (Object.keys(req.body).length > 0 ? JSON.stringify(req.body) : null) : null,
        };

        try {
            const result = await exports.handler(event);
            if (result.headers) {
                res.set(result.headers);
            }
            res.status(result.statusCode || 200).send(result.body);
        } catch (err) {
            console.error("Express Wrapper Error:", err);
            res.status(500).send(JSON.stringify({ success: false, message: 'Internal Server Error' }));
        }
    });

    const port = process.env.PORT || 3000;
    app.listen(port, () => {
        console.log(`Server is running on port ${port}`);
    });
}
