import { privateKeyToAccount } from "thirdweb/wallets";
import { verifySignature } from "thirdweb/auth";
import { NextRequest, NextResponse } from "next/server";
import { createThirdwebClient } from "thirdweb";

async function getClient() {
  const clientId = process.env.NEXT_PUBLIC_CLIENT_ID;

  if (!clientId) {
    throw new Error("No client ID provided");
  }

  return createThirdwebClient({ clientId });
}

async function getAdminAccount(client: any) {
  return privateKeyToAccount({
    privateKey: process.env.ADMIN_SECRET_KEY as string,
    client,
  });
}

 async function verifyTelegram(signature: string, message: string) {
  const client = await getClient();
  const adminAccount = await getAdminAccount(client);

  const metadata = JSON.parse(message);

  if (!metadata.expiration || metadata.expiration < Date.now()) {
    return false;
  }

  if (!metadata.username) {
    return false;
  }

  const isValid = await verifySignature({
    client,
    address: adminAccount.address,
    message: message,
    signature,
  });

  if (!isValid) {
    return false;
  }

  return metadata.username;
}

 async function POST(request: NextRequest) {
  const { payload } = await request.json();
  const { signature, message } = JSON.parse(payload);

  const userId = await verifyTelegram(signature, message);

  if (!userId) {
    return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
  }

  return NextResponse.json({ userId });
}
