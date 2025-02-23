use std::future::Future;
use std::pin::Pin;
use std::task::Poll;
use crate::rpc::MoonboisClient;
use crate::rpc::MoonboisClientError;
use pin_project::pin_project;
use solana_sdk::pubkey::Pubkey;

pub struct SnipeResult;

enum State<'a> {
    Idle,
    Polling(Pin<Box<dyn Future<Output = Result<bool, MoonboisClientError>> + Send + 'a>>),
}

#[pin_project]
pub struct PendingSnipe<'a> {
    pub snipe_id: String,
    pub deployer: Pubkey,
    provider: &'a MoonboisClient,
    state: State<'a>,
}

impl<'a> PendingSnipe<'a> {
    pub fn new(deployer: Pubkey, snipe_id: String, provider: &'a MoonboisClient) -> Self {
        Self {
            deployer,
            provider,
            snipe_id,
            state: State::Idle,
        }
    }
}

impl<'a> Future for PendingSnipe<'a> {
    type Output = Result<SnipeResult, MoonboisClientError>;

    fn poll(self: Pin<&mut Self>, ctx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.state {
            State::Idle => {
                let fut = Box::pin(this.provider.get_snipe_status(
                    this.deployer.clone(), 
                    this.snipe_id.clone()
                ));
                *this.state = State::Polling(fut);

                ctx.waker().wake_by_ref();
            },
            State::Polling(fut) => {
                match fut.as_mut().poll(ctx) {
                    Poll::Ready(Ok(result)) if !result => return Poll::Ready(Ok(SnipeResult)),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(_) => *this.state = State::Idle
                }
            }
        }

        Poll::Pending
    }
}
