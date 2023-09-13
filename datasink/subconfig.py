# Import any require subscibers here. The subscribers should implement the
# Subscriber class from subscriber.py
import datasink.subscribers as subs

# The thing to import from this module
subscriber_system = subs.SubscriberSystem()

# Register the desired subscribers here
subscriber_system.register_subscriber(subs.PrintSubscriber())
