use std::future::Future;
use std::future::IntoFuture;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;
use crate::rpc::MoonboisClient;
use crate::rpc::MoonboisClientError;
use crate::PendingSnipeError;
use crate::PumpfunSnipeStatus;
use pin_project::pin_project;
use solana_sdk::pubkey::Pubkey;
use tokio::time::sleep_until;
use tokio::time::Instant;

enum State<'a> {
    Idle,
    Sleeping(Pin<Box<dyn Future<Output = ()> + Send + 'a>>),
    Polling(Pin<Box<dyn Future<Output = Result<Option<PumpfunSnipeStatus>, MoonboisClientError>> + Send + 'a>>),
}

#[pin_project]
pub struct PendingSnipe<'a> {
    pub deployer: Pubkey,
    provider: &'a MoonboisClient,
    state: State<'a>,
}

impl<'a> PendingSnipe<'a> {
    pub fn new(deployer: Pubkey, provider: &'a MoonboisClient) -> Self {
        Self {
            deployer,
            provider,
            state: State::Idle,
        }
    }
}

impl<'a> Future for PendingSnipe<'a> {
    type Output = Result<(), PendingSnipeError>;

    fn poll(self: Pin<&mut Self>, ctx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.state {
            State::Idle => {
                let fut = Box::pin(this.provider.get_snipe_status(
                    this.deployer.clone()
                ));
                *this.state = State::Polling(fut);

                ctx.waker().wake_by_ref();
            },
            State::Sleeping(fut) => {
                match fut.as_mut().poll(ctx) {
                    Poll::Ready(_) => {
                        let fut = Box::pin(this.provider.get_snipe_status(
                            this.deployer.clone()
                        ));

                        *this.state = State::Polling(fut);
                        
                        ctx.waker().wake_by_ref();
                    }

                    Poll::Pending => return Poll::Pending
                }
            }
            State::Polling(fut) => {
                match fut.as_mut().poll(ctx) {
                    Poll::Ready(Ok(result)) => {
                        if let Some(result) = result {
                            match result {
                                PumpfunSnipeStatus::Complete => return Poll::Ready(Ok(())),
                                PumpfunSnipeStatus::CreateProjectFailed(err) => 
                                    return Poll::Ready(Err(PendingSnipeError::ProjectCreationFailed(err))),
                                PumpfunSnipeStatus::SnipeFailed(err) => 
                                    return Poll::Ready(Err(PendingSnipeError::SnipeFailed(err))),
                                PumpfunSnipeStatus::Pending => {
                                    let sleep_time = Instant::now() + Duration::from_secs(1);
                                    let fut = sleep_until(sleep_time).into_future();
            
                                    *this.state = State::Sleeping(Box::pin(fut));
            
                                    ctx.waker().wake_by_ref();
                                }
                            }
                        }
                    },
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err.into())),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        Poll::Pending
    }
}